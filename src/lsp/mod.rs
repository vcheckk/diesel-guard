use crate::SafetyChecker;
#[cfg(test)]
use crate::config::{Config, ConfigError};
use camino::{Utf8Path, Utf8PathBuf};
#[cfg(test)]
use lsp_server::{Connection, Message, Notification, Response};
#[cfg(test)]
use lsp_types::notification::Notification as LspNotification;
use lsp_types::{
    Diagnostic, DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, MessageType, Uri,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

mod checker;
mod config_cache;
mod diagnostic_output;
mod diagnostics;
mod protocol;
mod session;
mod transport;
mod uri;

use checker::{CheckerCache, CheckerCacheKey, CustomCheckFileSignature};
pub use config_cache::load_lsp_config;
#[cfg(test)]
use config_cache::{custom_checks_signature, file_content_hash};
use config_cache::{
    live_document_state, live_text_is_too_large, read_file_to_string_with_limit,
    saved_text_is_too_large,
};
use diagnostic_output::{CheckDiagnosticContext, ParseErrorOutput};
#[cfg(test)]
use diagnostics::byte_offset_to_position;
pub use diagnostics::violations_to_diagnostics;
use diagnostics::{check_live_sql, empty_event, final_full_sync_text};
pub use protocol::unsupported_request_response;
use protocol::{log_message_event, show_error_event};
#[cfg(test)]
use session::document_notification_kind;
pub use session::{initialize_result, run, select_workspace_root};
use transport::DocumentNotificationKind;
#[cfg(test)]
use uri::percent_decode_utf8;
pub use uri::{file_uri_to_path, is_sql_file_uri};

const SERVER_NAME: &str = "diesel-guard";
const DIAGNOSTIC_SOURCE: &str = "diesel-guard";
const MAX_LIVE_DOCUMENT_BYTES: usize = 1_000_000;
const MAX_SAVED_DOCUMENT_BYTES: u64 = 1_000_000;
const MAX_TRACKED_DOCUMENTS: usize = 256;
const MAX_PUBLISHED_DIAGNOSTIC_URIS: usize = 256;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_LSP_CUSTOM_CHECK_FILES: usize = 16;
const MAX_LSP_CUSTOM_CHECK_TOTAL_SOURCE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentState {
    pub text: Option<String>,
    pub version: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticEvent {
    pub uri: Uri,
    pub diagnostics: Vec<Diagnostic>,
    pub version: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub typ: MessageType,
    pub message: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HandlerOutput {
    pub diagnostics: Vec<DiagnosticEvent>,
    pub messages: Vec<MessageEvent>,
}

impl HandlerOutput {
    fn with_diagnostic(event: DiagnosticEvent) -> Self {
        Self {
            diagnostics: vec![event],
            messages: Vec::new(),
        }
    }
}

pub struct ServerState {
    root: Utf8PathBuf,
    documents: HashMap<Uri, DocumentState>,
    published_sql_uris: HashSet<Uri>,
    published_sql_uri_order: VecDeque<Uri>,
    checker_cache: Option<CheckerCache>,
    last_config_error_message: Option<String>,
    emitted_warning_messages: HashSet<String>,
    warned_incremental_change: bool,
    warned_unsupported_notification: bool,
    shutdown_requested: bool,
}

#[derive(Debug)]
enum LimitedFileRead {
    Text(String),
    TooLarge,
}

impl ServerState {
    pub fn new(root: Utf8PathBuf) -> Self {
        Self {
            root,
            documents: HashMap::new(),
            published_sql_uris: HashSet::new(),
            published_sql_uri_order: VecDeque::new(),
            checker_cache: None,
            last_config_error_message: None,
            emitted_warning_messages: HashSet::new(),
            warned_incremental_change: false,
            warned_unsupported_notification: false,
            shutdown_requested: false,
        }
    }

    pub fn document(&self, uri: &Uri) -> Option<&DocumentState> {
        self.documents.get(uri)
    }

    fn push_new_warning_messages(&mut self, output: &mut HandlerOutput, warnings: Vec<String>) {
        output
            .messages
            .extend(warnings.into_iter().filter_map(|warning| {
                self.emitted_warning_messages
                    .insert(warning.clone())
                    .then(|| log_message_event(warning))
            }));
    }

    pub fn handle_open(&mut self, params: DidOpenTextDocumentParams) -> HandlerOutput {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        let version = Some(params.text_document.version);
        if !is_sql_file_uri(&uri) {
            self.documents.remove(&uri);
            return self.clear_if_needed(uri, version);
        }
        self.store_document_state(uri.clone(), live_document_state(&text, version));
        self.run_live_diagnostics(uri, &text, version)
    }

    pub fn handle_change(&mut self, params: DidChangeTextDocumentParams) -> HandlerOutput {
        let uri = params.text_document.uri;
        let version = Some(params.text_document.version);
        if !is_sql_file_uri(&uri) {
            return self.handle_non_sql_change(uri, version);
        }

        let Some(text) = final_full_sync_text(&params.content_changes) else {
            return self.handle_incremental_change(uri, version);
        };

        if self.is_unchanged_document(&uri, text, version) {
            return HandlerOutput::default();
        }

        self.store_document_state(uri.clone(), live_document_state(text, version));
        self.run_live_diagnostics(uri, text, version)
    }

    fn handle_non_sql_change(&mut self, uri: Uri, version: Option<i32>) -> HandlerOutput {
        self.documents.remove(&uri);
        self.clear_if_needed(uri, version)
    }

    fn handle_incremental_change(&mut self, uri: Uri, version: Option<i32>) -> HandlerOutput {
        self.store_document_state(
            uri.clone(),
            DocumentState {
                text: None,
                version,
            },
        );
        let mut output = self.clear_if_needed(uri, version);
        self.push_incremental_change_warning(&mut output);
        output
    }

    fn push_incremental_change_warning(&mut self, output: &mut HandlerOutput) {
        if self.warned_incremental_change {
            return;
        }
        self.warned_incremental_change = true;
        output.messages.push(log_message_event(
            "Received incremental textDocument/didChange despite full-sync capability; diagnostics were cleared.",
        ));
    }

    fn is_unchanged_document(&self, uri: &Uri, text: &str, version: Option<i32>) -> bool {
        self.documents
            .get(uri)
            .is_some_and(|doc| doc.text.as_deref() == Some(text) && doc.version == version)
    }

    pub fn handle_save(&mut self, params: DidSaveTextDocumentParams) -> HandlerOutput {
        let uri = params.text_document.uri;
        if !is_sql_file_uri(&uri) {
            return self.clear_if_needed(uri, None);
        }

        let path = file_uri_to_path(&uri);
        let version = self.saved_document_version(&uri);
        let fallback_text = self.saved_document_text(&uri, params.text);

        if let Some(path) = path.as_deref() {
            return self.handle_save_with_file_path(uri, path, version, fallback_text);
        }

        self.handle_save_without_file_path(uri, version, fallback_text)
    }

    fn saved_document_version(&self, uri: &Uri) -> Option<i32> {
        self.documents.get(uri).and_then(|doc| doc.version)
    }

    fn saved_document_text(&self, uri: &Uri, explicit_text: Option<String>) -> Option<String> {
        explicit_text.or_else(|| self.documents.get(uri).and_then(|doc| doc.text.clone()))
    }

    fn handle_save_without_file_path(
        &mut self,
        uri: Uri,
        version: Option<i32>,
        fallback_text: Option<String>,
    ) -> HandlerOutput {
        let mut output = HandlerOutput::default();
        let Some(text) = fallback_text else {
            output.diagnostics.push(self.clear_event(uri, version));
            output.messages.push(show_error_event(
                "Saved SQL document has no readable file path or in-memory text.",
            ));
            return output;
        };

        if saved_text_is_too_large(&text) {
            self.push_clear_and_log(
                &mut output,
                uri,
                version,
                format!(
                    "Skipping saved-text diagnostics for SQL document larger than {MAX_SAVED_DOCUMENT_BYTES} bytes."
                ),
            );
            return output;
        }

        let (checker, output) = match self.load_checker_for_output(uri.clone(), version, output) {
            Ok(result) => result,
            Err(output) => return output,
        };
        self.run_saved_text_diagnostics(uri, &text, version, &checker, output)
    }

    fn handle_save_with_file_path(
        &mut self,
        uri: Uri,
        path: &Utf8Path,
        version: Option<i32>,
        fallback_text: Option<String>,
    ) -> HandlerOutput {
        match read_file_to_string_with_limit(path, MAX_SAVED_DOCUMENT_BYTES) {
            Ok(LimitedFileRead::Text(saved_text)) => {
                let output = HandlerOutput::default();
                self.run_saved_file_diagnostics(uri, path, &saved_text, version, output)
            }
            Ok(LimitedFileRead::TooLarge) => self.saved_file_too_large_output(uri, version),
            Err(err) => self.handle_unreadable_saved_file(uri, version, fallback_text, &err),
        }
    }

    fn saved_file_too_large_output(&mut self, uri: Uri, version: Option<i32>) -> HandlerOutput {
        let mut output = HandlerOutput::default();
        self.push_clear_and_log(
            &mut output,
            uri,
            version,
            format!(
                "Skipping saved-file diagnostics for SQL document larger than {MAX_SAVED_DOCUMENT_BYTES} bytes."
            ),
        );
        output
    }

    fn handle_unreadable_saved_file(
        &mut self,
        uri: Uri,
        version: Option<i32>,
        fallback_text: Option<String>,
        err: &std::io::Error,
    ) -> HandlerOutput {
        let mut output = HandlerOutput::default();
        let Some(text) = fallback_text else {
            output.diagnostics.push(self.clear_event(uri, version));
            output.messages.push(show_error_event(format!(
                "Failed to read saved SQL file: {err}"
            )));
            return output;
        };
        if saved_text_is_too_large(&text) {
            self.push_clear_and_log(
                &mut output,
                uri,
                version,
                format!(
                    "Skipping saved-text diagnostics for SQL document larger than {MAX_SAVED_DOCUMENT_BYTES} bytes."
                ),
            );
            return output;
        }
        let (checker, mut output) = match self.load_checker_for_output(uri.clone(), version, output)
        {
            Ok(result) => result,
            Err(output) => return output,
        };
        output.messages.push(log_message_event(format!(
            "Saved SQL file was not readable; checked in-memory text without migration metadata: {err}"
        )));
        self.run_saved_text_diagnostics(uri, &text, version, &checker, output)
    }

    fn push_clear_and_log(
        &mut self,
        output: &mut HandlerOutput,
        uri: Uri,
        version: Option<i32>,
        message: impl Into<String>,
    ) {
        output.diagnostics.push(self.clear_event(uri, version));
        output.messages.push(log_message_event(message));
    }

    fn load_checker_for_output(
        &mut self,
        uri: Uri,
        version: Option<i32>,
        mut output: HandlerOutput,
    ) -> std::result::Result<(Arc<SafetyChecker>, HandlerOutput), HandlerOutput> {
        match self.load_checker() {
            Ok((checker, warnings)) => {
                self.push_new_warning_messages(&mut output, warnings);
                Ok((checker, output))
            }
            Err(err) => Err(self.config_error_output(uri, version, &err)),
        }
    }

    fn run_saved_file_diagnostics(
        &mut self,
        uri: Uri,
        path: &Utf8Path,
        saved_text: &str,
        version: Option<i32>,
        output: HandlerOutput,
    ) -> HandlerOutput {
        let (checker, output) = match self.load_checker_for_output(uri.clone(), version, output) {
            Ok(result) => result,
            Err(output) => return output,
        };
        let check_result = checker.check_file_sql_with_warnings(path, saved_text);
        self.apply_check_result(
            CheckDiagnosticContext {
                uri,
                version,
                parse_error_output: ParseErrorOutput::PublishDiagnostic,
                error_context: "Failed to check saved SQL file",
            },
            saved_text,
            output,
            check_result,
        )
    }

    fn run_saved_text_diagnostics(
        &mut self,
        uri: Uri,
        text: &str,
        version: Option<i32>,
        checker: &SafetyChecker,
        mut output: HandlerOutput,
    ) -> HandlerOutput {
        if saved_text_is_too_large(text) {
            output.diagnostics.push(self.clear_event(uri, version));
            output.messages.push(log_message_event(format!(
                "Skipping saved-text diagnostics for SQL document larger than {MAX_SAVED_DOCUMENT_BYTES} bytes."
            )));
            return output;
        }

        let check_result = checker.check_sql_with_warnings(text);
        self.apply_check_result(
            CheckDiagnosticContext {
                uri,
                version,
                parse_error_output: ParseErrorOutput::PublishDiagnostic,
                error_context: "Failed to check saved SQL text",
            },
            text,
            output,
            check_result,
        )
    }

    pub fn handle_close(&mut self, params: DidCloseTextDocumentParams) -> HandlerOutput {
        let uri = params.text_document.uri;
        self.documents.remove(&uri);
        let was_published = self.untrack_published_uri(&uri);
        if is_sql_file_uri(&uri) || was_published {
            HandlerOutput::with_diagnostic(empty_event(uri, None))
        } else {
            HandlerOutput::default()
        }
    }

    fn store_document_state(&mut self, uri: Uri, state: DocumentState) {
        if !self.documents.contains_key(&uri)
            && self.documents.len() >= MAX_TRACKED_DOCUMENTS
            && let Some(evicted_uri) = self.documents.keys().next().cloned()
        {
            self.documents.remove(&evicted_uri);
        }
        self.documents.insert(uri, state);
    }

    fn run_live_diagnostics(
        &mut self,
        uri: Uri,
        text: &str,
        version: Option<i32>,
    ) -> HandlerOutput {
        if let Some(output) = self.live_diagnostics_precheck(&uri, text, version) {
            return output;
        }

        let output = HandlerOutput::default();
        let (checker, output) = match self.load_checker_for_output(uri.clone(), version, output) {
            Ok(result) => result,
            Err(output) => return output,
        };

        let check_result = check_live_sql(&checker, &uri, text);
        self.apply_check_result(
            CheckDiagnosticContext {
                uri,
                version,
                parse_error_output: ParseErrorOutput::ClearOnly,
                error_context: "Failed to check SQL document",
            },
            text,
            output,
            check_result,
        )
    }

    fn live_diagnostics_precheck(
        &mut self,
        uri: &Uri,
        text: &str,
        version: Option<i32>,
    ) -> Option<HandlerOutput> {
        if !is_sql_file_uri(uri) {
            return Some(self.clear_if_needed(uri.clone(), version));
        }

        live_text_is_too_large(text).then(|| self.oversized_live_output(uri.clone(), version))
    }

    fn oversized_live_output(&mut self, uri: Uri, version: Option<i32>) -> HandlerOutput {
        let mut output = self.clear_if_needed(uri, version);
        output.messages.push(log_message_event(format!(
            "Skipping live diagnostics for SQL document larger than {MAX_LIVE_DOCUMENT_BYTES} bytes; very large live and saved SQL documents are skipped to keep the editor responsive."
        )));
        output
    }
}

#[cfg(test)]
mod tests;
