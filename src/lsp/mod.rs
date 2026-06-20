use crate::config::{Config, ConfigError};
use crate::error::{DieselGuardError, Result};
use crate::{SafetyChecker, ViolationList};
use camino::{Utf8Path, Utf8PathBuf};
use lsp_server::{Connection, ErrorCode, Message, Notification, Response};
use lsp_types::notification::Notification as LspNotification;
use lsp_types::{
    Diagnostic, DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, MessageType, Uri,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

mod config_cache;
mod diagnostics;
mod protocol;
mod session;
mod uri;

pub use config_cache::load_lsp_config;
use config_cache::{
    checker_cache_key_with_lsp_fallback, live_document_state, live_text_is_too_large,
    read_file_to_string_with_limit, saved_text_is_too_large,
};
#[cfg(test)]
use config_cache::{custom_checks_signature, file_content_hash};
#[cfg(test)]
use diagnostics::byte_offset_to_position;
pub use diagnostics::violations_to_diagnostics;
use diagnostics::{
    check_live_sql, empty_event, final_full_sync_text, is_parse_error, parse_error_event,
};
pub use protocol::unsupported_request_response;
use protocol::{
    deserialize_error_output, log_message_event, protocol_error, publish_diagnostics,
    publish_log_messages, send_response, show_error_event,
};
use session::{document_notification_kind, is_initialized_notification};
pub use session::{initialize_result, run, select_workspace_root};
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

    fn push_messages(&mut self, warnings: Vec<String>) {
        self.messages
            .extend(warnings.into_iter().map(log_message_event));
    }
}

pub struct ServerState {
    root: Utf8PathBuf,
    documents: HashMap<Uri, DocumentState>,
    published_sql_uris: HashSet<Uri>,
    published_sql_uri_order: VecDeque<Uri>,
    checker_cache: Option<CheckerCache>,
    last_config_error_message: Option<String>,
    warned_incremental_change: bool,
    warned_unsupported_notification: bool,
    shutdown_requested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopControl {
    Continue,
    Exit(i32),
}

struct CheckerCache {
    key: CheckerCacheKey,
    checker: Arc<SafetyChecker>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckerCacheKey {
    config: String,
    custom_checks_signature: Vec<CustomCheckFileSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CustomCheckFileSignature {
    path: String,
    modified: Option<SystemTime>,
    len: Option<u64>,
    content_hash: Option<u64>,
}

#[derive(Debug)]
enum LimitedFileRead {
    Text(String),
    TooLarge,
}

#[derive(Clone, Copy)]
enum ParseErrorOutput {
    PublishDiagnostic,
    ClearOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DocumentNotificationKind {
    Open,
    Change,
    Save,
    Close,
}

impl DocumentNotificationKind {
    fn handle(self, state: &mut ServerState, params: serde_json::Value) -> HandlerOutput {
        match self {
            Self::Open => {
                state.handle_typed_notification("didOpen", params, ServerState::handle_open)
            }
            Self::Change => {
                state.handle_typed_notification("didChange", params, ServerState::handle_change)
            }
            Self::Save => {
                state.handle_typed_notification("didSave", params, ServerState::handle_save)
            }
            Self::Close => {
                state.handle_typed_notification("didClose", params, ServerState::handle_close)
            }
        }
    }
}

struct CheckDiagnosticContext<'a> {
    uri: Uri,
    version: Option<i32>,
    parse_error_output: ParseErrorOutput,
    error_context: &'a str,
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
            warned_incremental_change: false,
            warned_unsupported_notification: false,
            shutdown_requested: false,
        }
    }

    pub fn document(&self, uri: &Uri) -> Option<&DocumentState> {
        self.documents.get(uri)
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
                output.push_messages(warnings);
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

    fn apply_check_result(
        &mut self,
        context: CheckDiagnosticContext<'_>,
        text: &str,
        mut output: HandlerOutput,
        check_result: Result<(ViolationList, Vec<String>)>,
    ) -> HandlerOutput {
        match check_result {
            Ok((violations, check_warnings)) => {
                self.append_successful_diagnostics(
                    context.uri,
                    text,
                    context.version,
                    &mut output,
                    &violations,
                    check_warnings,
                );
            }
            Err(err) if is_parse_error(&err) => self.append_parse_error_diagnostics(
                context.uri,
                text,
                context.version,
                &mut output,
                &err,
                context.parse_error_output,
            ),
            Err(err) => self.append_check_error(
                context.uri,
                context.version,
                &mut output,
                context.error_context,
                &err,
            ),
        }
        output
    }

    fn append_successful_diagnostics(
        &mut self,
        uri: Uri,
        text: &str,
        version: Option<i32>,
        output: &mut HandlerOutput,
        violations: &ViolationList,
        check_warnings: Vec<String>,
    ) {
        output.push_messages(check_warnings);
        output
            .diagnostics
            .extend(self.violations_events(uri, text, violations, version));
    }

    fn append_parse_error_diagnostics(
        &mut self,
        uri: Uri,
        text: &str,
        version: Option<i32>,
        output: &mut HandlerOutput,
        err: &DieselGuardError,
        parse_error_output: ParseErrorOutput,
    ) {
        match parse_error_output {
            ParseErrorOutput::PublishDiagnostic => output
                .diagnostics
                .extend(self.parse_error_diagnostics_events(uri, text, err, version)),
            ParseErrorOutput::ClearOnly => output.diagnostics.push(self.clear_event(uri, version)),
        }
    }

    fn append_check_error(
        &mut self,
        uri: Uri,
        version: Option<i32>,
        output: &mut HandlerOutput,
        context: &str,
        err: &DieselGuardError,
    ) {
        output.diagnostics.push(self.clear_event(uri, version));
        output
            .messages
            .push(show_error_event(format!("{context}: {err}")));
    }

    fn clear_if_needed(&mut self, uri: Uri, version: Option<i32>) -> HandlerOutput {
        if self.untrack_published_uri(&uri) {
            HandlerOutput::with_diagnostic(empty_event(uri, version))
        } else {
            HandlerOutput::default()
        }
    }

    fn config_error_output(
        &mut self,
        uri: Uri,
        version: Option<i32>,
        err: &ConfigError,
    ) -> HandlerOutput {
        let mut output = HandlerOutput::with_diagnostic(self.clear_event(uri, version));
        let message = format!("Failed to load diesel-guard configuration for the workspace: {err}");
        if self.last_config_error_message.as_deref() != Some(message.as_str()) {
            self.last_config_error_message = Some(message.clone());
            output.messages.push(show_error_event(message));
        }
        output
    }

    fn clear_event(&mut self, uri: Uri, version: Option<i32>) -> DiagnosticEvent {
        self.untrack_published_uri(&uri);
        empty_event(uri, version)
    }

    fn parse_error_diagnostics_events(
        &mut self,
        uri: Uri,
        text: &str,
        err: &DieselGuardError,
        version: Option<i32>,
    ) -> Vec<DiagnosticEvent> {
        let mut events = self.track_published_uri(&uri);
        events.push(parse_error_event(uri, text, err, version));
        events
    }

    fn violations_events(
        &mut self,
        uri: Uri,
        text: &str,
        violations: &ViolationList,
        version: Option<i32>,
    ) -> Vec<DiagnosticEvent> {
        let diagnostics = violations_to_diagnostics(text, violations);
        let mut events = if diagnostics.is_empty() {
            self.untrack_published_uri(&uri);
            Vec::new()
        } else {
            self.track_published_uri(&uri)
        };
        events.push(DiagnosticEvent {
            uri,
            diagnostics,
            version,
        });
        events
    }

    fn track_published_uri(&mut self, uri: &Uri) -> Vec<DiagnosticEvent> {
        if self.published_sql_uris.insert(uri.clone()) {
            self.published_sql_uri_order.push_back(uri.clone());
        }

        let mut events = Vec::new();
        while self.published_sql_uris.len() > MAX_PUBLISHED_DIAGNOSTIC_URIS {
            let Some(evicted_uri) = self.published_sql_uri_order.pop_front() else {
                break;
            };
            if self.published_sql_uris.remove(&evicted_uri) {
                events.push(empty_event(evicted_uri, None));
            }
        }
        events
    }

    fn untrack_published_uri(&mut self, uri: &Uri) -> bool {
        let removed = self.published_sql_uris.remove(uri);
        if removed {
            self.published_sql_uri_order
                .retain(|tracked_uri| tracked_uri != uri);
        }
        removed
    }

    fn load_checker(
        &mut self,
    ) -> std::result::Result<(Arc<SafetyChecker>, Vec<String>), ConfigError> {
        let (config, key, cache_warnings) = self.load_checker_inputs()?;

        if let Some(checker) = self.cached_checker(&key) {
            return Ok((checker, Vec::new()));
        }

        Ok(self.build_cached_checker(config, key, cache_warnings))
    }

    fn load_checker_inputs(
        &self,
    ) -> std::result::Result<(Config, CheckerCacheKey, Vec<String>), ConfigError> {
        let mut config = load_lsp_config(&self.root)?;
        let mut cache_warnings = Vec::new();
        let key = checker_cache_key_with_lsp_fallback(&mut config, &mut cache_warnings)?;
        Ok((config, key, cache_warnings))
    }

    fn cached_checker(&mut self, key: &CheckerCacheKey) -> Option<Arc<SafetyChecker>> {
        let checker = self
            .checker_cache
            .as_ref()
            .filter(|cache| cache.key == *key)
            .map(|cache| Arc::clone(&cache.checker))?;
        self.last_config_error_message = None;
        Some(checker)
    }

    fn build_cached_checker(
        &mut self,
        config: Config,
        key: CheckerCacheKey,
        cache_warnings: Vec<String>,
    ) -> (Arc<SafetyChecker>, Vec<String>) {
        let (checker, mut warnings) = SafetyChecker::with_config_and_warnings(config);
        warnings.splice(0..0, cache_warnings);
        let checker = Arc::new(checker);
        self.checker_cache = Some(CheckerCache {
            key,
            checker: Arc::clone(&checker),
        });
        self.last_config_error_message = None;
        (checker, warnings)
    }

    fn apply_output(connection: &Connection, output: HandlerOutput) -> Result<()> {
        publish_diagnostics(connection, output.diagnostics)?;
        publish_log_messages(connection, output.messages)?;
        Ok(())
    }

    fn run_loop(&mut self, connection: &Connection) -> Result<i32> {
        for message in &connection.receiver {
            match self.handle_message(connection, message)? {
                LoopControl::Continue => {}
                LoopControl::Exit(code) => return Ok(code),
            }
        }

        Ok(0)
    }

    fn handle_message(&mut self, connection: &Connection, message: Message) -> Result<LoopControl> {
        match message {
            Message::Request(request) => self.handle_request_message(connection, request),
            Message::Notification(notification) => {
                self.handle_notification_message(connection, notification)
            }
            Message::Response(_) => Ok(LoopControl::Continue),
        }
    }

    fn handle_request_message(
        &mut self,
        connection: &Connection,
        request: lsp_server::Request,
    ) -> Result<LoopControl> {
        if connection
            .handle_shutdown(&request)
            .map_err(protocol_error)?
        {
            self.shutdown_requested = true;
            return Ok(LoopControl::Continue);
        }

        send_response(
            connection,
            Response::new_err(
                request.id,
                ErrorCode::MethodNotFound as i32,
                format!("Unsupported request method: {}", request.method),
            ),
        )?;
        Ok(LoopControl::Continue)
    }

    fn handle_notification_message(
        &mut self,
        connection: &Connection,
        notification: Notification,
    ) -> Result<LoopControl> {
        if notification.method == lsp_types::notification::Exit::METHOD {
            return Ok(LoopControl::Exit(i32::from(!self.shutdown_requested)));
        }

        let output = self.handle_notification(notification);
        Self::apply_output(connection, output)?;
        Ok(LoopControl::Continue)
    }

    fn handle_notification(&mut self, notification: Notification) -> HandlerOutput {
        let method = notification.method.as_str();
        if is_initialized_notification(method) {
            return HandlerOutput::default();
        }
        self.handle_document_notification(method, notification.params)
            .unwrap_or_else(|| self.unsupported_notification_output(method))
    }

    fn handle_document_notification(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Option<HandlerOutput> {
        let kind = document_notification_kind(method)?;
        Some(kind.handle(self, params))
    }

    fn handle_typed_notification<T>(
        &mut self,
        method_label: &str,
        params: serde_json::Value,
        handler: fn(&mut Self, T) -> HandlerOutput,
    ) -> HandlerOutput
    where
        T: serde::de::DeserializeOwned,
    {
        match serde_json::from_value(params) {
            Ok(params) => handler(self, params),
            Err(err) => deserialize_error_output(method_label, &err),
        }
    }

    fn unsupported_notification_output(&mut self, method: &str) -> HandlerOutput {
        let mut output = HandlerOutput::default();
        if !self.warned_unsupported_notification {
            self.warned_unsupported_notification = true;
            output.messages.push(log_message_event(format!(
                "Ignoring unsupported notification: {method}"
            )));
        }
        output
    }
}

#[cfg(test)]
mod tests;
