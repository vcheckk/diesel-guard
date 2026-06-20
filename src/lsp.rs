use crate::config::{Config, ConfigError};
use crate::error::{DieselGuardError, Result};
use crate::scripting::{MAX_CUSTOM_CHECK_DIR_ENTRIES, MAX_CUSTOM_CHECK_SOURCE_BYTES};
use crate::violation::Severity;
use crate::{SafetyChecker, ViolationList};
use camino::{Utf8Path, Utf8PathBuf};
use lsp_server::{
    Connection, ErrorCode, IoThreads, Message, Notification, RequestId, Response, ResponseError,
};
use lsp_types::notification::Notification as LspNotification;
use lsp_types::{
    Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DidSaveTextDocumentParams, InitializeParams, InitializeResult,
    LogMessageParams, MessageType, NumberOrString, Position, PublishDiagnosticsParams, Range,
    SaveOptions, ServerCapabilities, ServerInfo, TextDocumentContentChangeEvent,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions,
    TextDocumentSyncSaveOptions, Uri,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::sync::Arc;
use std::time::SystemTime;

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

pub fn run() -> Result<()> {
    let (connection, io_threads) = Connection::stdio();
    run_stdio_session(connection, io_threads)
}

fn run_stdio_session(connection: Connection, io_threads: IoThreads) -> Result<()> {
    let root = initialize_connection(&connection)?;
    let exit_code = ServerState::new(root).run_loop(&connection)?;
    drop(connection);
    io_threads.join()?;
    exit_with_code(exit_code);
    Ok(())
}

fn initialize_connection(connection: &Connection) -> Result<Utf8PathBuf> {
    let (initialize_id, params) = start_initialize(connection)?;
    let cwd = current_utf8_dir()?;
    let root = select_workspace_root(&params, &cwd);
    finish_initialize(connection, initialize_id)?;
    Ok(root)
}

fn start_initialize(connection: &Connection) -> Result<(RequestId, InitializeParams)> {
    let (initialize_id, initialize_params) =
        connection.initialize_start().map_err(protocol_error)?;
    let params = decode_initialize_params(initialize_params)?;
    Ok((initialize_id, params))
}

fn decode_initialize_params(value: serde_json::Value) -> Result<InitializeParams> {
    serde_json::from_value(value)
        .map_err(|err| DieselGuardError::parse_error(format!("Invalid initialize params: {err}")))
}

fn finish_initialize(connection: &Connection, initialize_id: RequestId) -> Result<()> {
    let result = serde_json::to_value(initialize_result())
        .map_err(|err| DieselGuardError::parse_error(err.to_string()))?;
    connection
        .initialize_finish(initialize_id, result)
        .map_err(protocol_error)
}

fn exit_with_code(exit_code: i32) {
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

pub fn initialize_result() -> InitializeResult {
    InitializeResult {
        capabilities: ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Options(
                TextDocumentSyncOptions {
                    open_close: Some(true),
                    change: Some(TextDocumentSyncKind::FULL),
                    save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                        include_text: Some(true),
                    })),
                    ..TextDocumentSyncOptions::default()
                },
            )),
            ..ServerCapabilities::default()
        },
        server_info: Some(ServerInfo {
            name: SERVER_NAME.to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }),
    }
}

fn is_initialized_notification(method: &str) -> bool {
    method == lsp_types::notification::Initialized::METHOD
}

fn document_notification_kind(method: &str) -> Option<DocumentNotificationKind> {
    document_notification_kinds()
        .into_iter()
        .find_map(|(candidate, kind)| (method == candidate).then_some(kind))
}

fn document_notification_kinds() -> [(&'static str, DocumentNotificationKind); 4] {
    [
        (
            lsp_types::notification::DidOpenTextDocument::METHOD,
            DocumentNotificationKind::Open,
        ),
        (
            lsp_types::notification::DidChangeTextDocument::METHOD,
            DocumentNotificationKind::Change,
        ),
        (
            lsp_types::notification::DidSaveTextDocument::METHOD,
            DocumentNotificationKind::Save,
        ),
        (
            lsp_types::notification::DidCloseTextDocument::METHOD,
            DocumentNotificationKind::Close,
        ),
    ]
}

pub fn select_workspace_root(params: &InitializeParams, current_dir: &Utf8Path) -> Utf8PathBuf {
    params
        .workspace_folders
        .as_ref()
        .and_then(|folders| folders.first())
        .and_then(|folder| file_uri_to_path(&folder.uri))
        .or_else(|| {
            #[allow(deprecated)]
            params.root_uri.as_ref().and_then(file_uri_to_path)
        })
        .unwrap_or_else(|| current_dir.to_path_buf())
}

pub fn load_lsp_config(root: &Utf8Path) -> std::result::Result<Config, ConfigError> {
    let mut config = Config::load_from_dir_with_limit(root, MAX_CONFIG_BYTES)?;
    if let Some(custom_checks_dir) = config.custom_checks_dir.as_deref() {
        let path = Utf8Path::new(custom_checks_dir);
        if path.is_relative() {
            config.custom_checks_dir = Some(root.join(path).to_string());
        }
    }
    Ok(config)
}

fn live_document_state(text: &str, version: Option<i32>) -> DocumentState {
    DocumentState {
        text: (text.len() <= MAX_LIVE_DOCUMENT_BYTES).then(|| text.to_string()),
        version,
    }
}

fn saved_text_is_too_large(text: &str) -> bool {
    text.len() > usize::try_from(MAX_SAVED_DOCUMENT_BYTES).unwrap_or(usize::MAX)
}

fn live_text_is_too_large(text: &str) -> bool {
    text.len() > MAX_LIVE_DOCUMENT_BYTES
}

fn checker_cache_key(config: &Config) -> std::result::Result<CheckerCacheKey, ConfigError> {
    Ok(CheckerCacheKey {
        config: format!("{config:?}"),
        custom_checks_signature: custom_checks_signature(config)?,
    })
}

fn checker_cache_key_with_lsp_fallback(
    config: &mut Config,
    cache_warnings: &mut Vec<String>,
) -> std::result::Result<CheckerCacheKey, ConfigError> {
    match checker_cache_key(config) {
        Ok(key) => Ok(key),
        Err(ConfigError::CustomChecksTooLarge { message }) => {
            cache_warnings.push(format!(
                "Custom checks are disabled for LSP diagnostics: {message}"
            ));
            config.custom_checks_dir = None;
            checker_cache_key(config)
        }
        Err(err) => Err(err),
    }
}

fn custom_checks_signature(
    config: &Config,
) -> std::result::Result<Vec<CustomCheckFileSignature>, ConfigError> {
    let Some((custom_checks_dir, entries)) = custom_check_signature_entries(config) else {
        return Ok(Vec::new());
    };
    collect_custom_checks_signature(custom_checks_dir, entries)
}

fn custom_check_signature_entries(config: &Config) -> Option<(&str, std::fs::ReadDir)> {
    let custom_checks_dir = config.custom_checks_dir.as_deref()?;
    let Ok(entries) = std::fs::read_dir(Utf8Path::new(custom_checks_dir)) else {
        return None;
    };
    Some((custom_checks_dir, entries))
}

fn collect_custom_checks_signature(
    custom_checks_dir: &str,
    entries: std::fs::ReadDir,
) -> std::result::Result<Vec<CustomCheckFileSignature>, ConfigError> {
    let mut signature = Vec::new();
    let mut total_hash_bytes = 0_u64;

    for (index, entry) in entries.enumerate() {
        enforce_custom_check_entry_limit(index, custom_checks_dir)?;

        let Some(path) = lsp_custom_check_file_path(entry) else {
            continue;
        };
        enforce_custom_check_file_limit(&signature, custom_checks_dir)?;

        let file_signature = custom_check_file_signature(&path, &mut total_hash_bytes)?;
        signature.push(file_signature);
    }

    signature.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(signature)
}

fn enforce_custom_check_entry_limit(
    index: usize,
    custom_checks_dir: &str,
) -> std::result::Result<(), ConfigError> {
    if index >= MAX_CUSTOM_CHECK_DIR_ENTRIES {
        return Err(custom_checks_too_large(format!(
            "more than {MAX_CUSTOM_CHECK_DIR_ENTRIES} directory entries in {custom_checks_dir}"
        )));
    }
    Ok(())
}

fn lsp_custom_check_file_path(
    entry: std::io::Result<std::fs::DirEntry>,
) -> Option<std::path::PathBuf> {
    let entry = entry.ok()?;
    let path = entry.path();
    if path.extension().is_none_or(|extension| extension != "rhai") {
        return None;
    }
    if !entry.file_type().ok()?.is_file() {
        return None;
    }
    Some(path)
}

fn enforce_custom_check_file_limit(
    signature: &[CustomCheckFileSignature],
    custom_checks_dir: &str,
) -> std::result::Result<(), ConfigError> {
    if signature.len() >= MAX_LSP_CUSTOM_CHECK_FILES {
        return Err(custom_checks_too_large(format!(
            "more than {MAX_LSP_CUSTOM_CHECK_FILES} .rhai custom check files in {custom_checks_dir}"
        )));
    }
    Ok(())
}

fn custom_check_file_signature(
    path: &std::path::Path,
    total_hash_bytes: &mut u64,
) -> std::result::Result<CustomCheckFileSignature, ConfigError> {
    let metadata = std::fs::metadata(path).ok();
    let len = metadata.as_ref().map(std::fs::Metadata::len);
    let content_hash = custom_check_signature_hash(path, len, total_hash_bytes)?;
    Ok(custom_check_signature_from_parts(
        path,
        metadata.as_ref(),
        len,
        content_hash,
    ))
}

fn custom_check_signature_hash(
    path: &std::path::Path,
    len: Option<u64>,
    total_hash_bytes: &mut u64,
) -> std::result::Result<Option<u64>, ConfigError> {
    if len.is_none_or(|len| len > MAX_CUSTOM_CHECK_SOURCE_BYTES) {
        return Ok(None);
    }

    let Some((hash, bytes_read)) = file_content_hash(path)? else {
        return Ok(None);
    };
    enforce_lsp_custom_check_hash_budget(total_hash_bytes, bytes_read)?;
    Ok(Some(hash))
}

fn enforce_lsp_custom_check_hash_budget(
    total_hash_bytes: &mut u64,
    bytes_read: u64,
) -> std::result::Result<(), ConfigError> {
    let next_total = total_hash_bytes.saturating_add(bytes_read);
    if next_total > MAX_LSP_CUSTOM_CHECK_TOTAL_SOURCE_BYTES {
        return Err(custom_checks_too_large(format!(
            "more than {MAX_LSP_CUSTOM_CHECK_TOTAL_SOURCE_BYTES} bytes of custom check content would be hashed"
        )));
    }
    *total_hash_bytes = next_total;
    Ok(())
}

fn custom_check_signature_from_parts(
    path: &std::path::Path,
    metadata: Option<&std::fs::Metadata>,
    len: Option<u64>,
    content_hash: Option<u64>,
) -> CustomCheckFileSignature {
    CustomCheckFileSignature {
        path: path.display().to_string(),
        modified: metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok()),
        len,
        content_hash,
    }
}

fn file_content_hash(
    path: &std::path::Path,
) -> std::result::Result<Option<(u64, u64)>, ConfigError> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(None);
    };
    let mut reader = file.take(MAX_CUSTOM_CHECK_SOURCE_BYTES.saturating_add(1));
    let mut bytes = Vec::new();
    if reader.read_to_end(&mut bytes).is_err() {
        return Ok(None);
    }
    let bytes_read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if bytes_read > MAX_CUSTOM_CHECK_SOURCE_BYTES {
        return Err(custom_checks_too_large(format!(
            "custom check file grew beyond {MAX_CUSTOM_CHECK_SOURCE_BYTES} bytes while hashing: {}",
            path.display()
        )));
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    Ok(Some((hasher.finish(), bytes_read)))
}

fn custom_checks_too_large(message: String) -> ConfigError {
    ConfigError::CustomChecksTooLarge { message }
}

fn read_file_to_string_with_limit(path: &Utf8Path, limit: u64) -> std::io::Result<LimitedFileRead> {
    ensure_regular_file(path)?;
    let bytes = read_file_bytes_with_limit(path, limit)?;
    limited_bytes_to_string(bytes, limit)
}

fn ensure_regular_file(path: &Utf8Path) -> std::io::Result<()> {
    let file_type = std::fs::symlink_metadata(path)?.file_type();
    if !file_type.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    Ok(())
}

fn read_file_bytes_with_limit(path: &Utf8Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut reader = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn limited_bytes_to_string(bytes: Vec<u8>, limit: u64) -> std::io::Result<LimitedFileRead> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Ok(LimitedFileRead::TooLarge);
    }
    String::from_utf8(bytes)
        .map(LimitedFileRead::Text)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

pub fn is_sql_file_uri(uri: &Uri) -> bool {
    file_uri_to_path(uri).is_some_and(|path| {
        path.extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
    })
}

pub fn file_uri_to_path(uri: &Uri) -> Option<Utf8PathBuf> {
    let rest = strip_file_uri(uri)?;
    let path = file_uri_local_path(rest)?;
    let path = path_without_query_or_fragment(&path);
    let path = percent_decode_utf8(path).ok()?;
    #[cfg(windows)]
    let path = path.strip_prefix('/').unwrap_or(&path).to_string();

    Some(Utf8PathBuf::from(path))
}

fn strip_file_uri(uri: &Uri) -> Option<&str> {
    uri.as_str().strip_prefix("file://")
}

fn file_uri_local_path(rest: &str) -> Option<String> {
    if let Some(path) = rest.strip_prefix('/') {
        return Some(format!("/{path}"));
    }

    let slash = rest.find('/')?;
    let authority = &rest[..slash];
    validate_file_uri_authority(authority)?;
    Some(rest[slash..].to_string())
}

fn validate_file_uri_authority(authority: &str) -> Option<()> {
    (authority.is_empty() || authority == "localhost").then_some(())
}

fn path_without_query_or_fragment(path: &str) -> &str {
    path.split(['?', '#']).next().unwrap_or(path)
}

fn check_live_sql(
    checker: &SafetyChecker,
    uri: &Uri,
    text: &str,
) -> Result<(ViolationList, Vec<String>)> {
    file_uri_to_path(uri).map_or_else(
        || checker.check_sql_with_warnings(text),
        |path| checker.check_file_sql_with_warnings(&path, text),
    )
}

pub fn violations_to_diagnostics(text: &str, violations: &ViolationList) -> Vec<Diagnostic> {
    let lines = text.lines().collect::<Vec<_>>();
    violations
        .iter()
        .map(|(line, violation)| {
            Diagnostic::new(
                diagnostic_range(*line, &lines),
                Some(diagnostic_severity(violation.severity)),
                diagnostic_code(&violation.check_name),
                Some(DIAGNOSTIC_SOURCE.to_string()),
                diagnostic_message(&violation.problem, &violation.safe_alternative),
                None,
                None,
            )
        })
        .collect()
}

fn diagnostic_range(line: usize, lines: &[&str]) -> Range {
    let zero_indexed_line = u32::try_from(line.saturating_sub(1)).unwrap_or(u32::MAX);
    let line_text = lines
        .get(line.saturating_sub(1))
        .copied()
        .unwrap_or_default();
    line_range(zero_indexed_line, line_text)
}

fn diagnostic_severity(severity: Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
    }
}

fn diagnostic_code(check_name: &str) -> Option<NumberOrString> {
    (!check_name.is_empty()).then(|| NumberOrString::String(check_name.to_string()))
}

fn parse_error_event(
    uri: Uri,
    text: &str,
    err: &DieselGuardError,
    version: Option<i32>,
) -> DiagnosticEvent {
    let offset = match err {
        DieselGuardError::ParseError { span, .. } => {
            span.as_ref().map_or(0, miette::SourceSpan::offset)
        }
        _ => 0,
    };
    let position = byte_offset_to_position(text, offset);
    let range = Range {
        start: position,
        end: position,
    };
    DiagnosticEvent {
        uri,
        diagnostics: vec![Diagnostic::new(
            range,
            Some(DiagnosticSeverity::ERROR),
            Some(NumberOrString::String("ParseError".to_string())),
            Some(DIAGNOSTIC_SOURCE.to_string()),
            err.to_string(),
            None,
            None,
        )],
        version,
    }
}

fn empty_event(uri: Uri, version: Option<i32>) -> DiagnosticEvent {
    DiagnosticEvent {
        uri,
        diagnostics: Vec::new(),
        version,
    }
}

fn final_full_sync_text(changes: &[TextDocumentContentChangeEvent]) -> Option<&str> {
    changes
        .iter()
        .rev()
        .find(|change| change.range.is_none())
        .map(|change| change.text.as_str())
}

fn line_range(line: u32, line_text: &str) -> Range {
    let end_character = line_text.encode_utf16().count();
    Range {
        start: Position { line, character: 0 },
        end: Position {
            line,
            character: u32::try_from(end_character).unwrap_or(u32::MAX),
        },
    }
}

fn diagnostic_message(problem: &str, safe_alternative: &str) -> String {
    if safe_alternative.is_empty() {
        problem.to_string()
    } else {
        format!("{problem} Safe alternative: {safe_alternative}")
    }
}

fn is_parse_error(err: &DieselGuardError) -> bool {
    matches!(err, DieselGuardError::ParseError { .. })
}

fn byte_offset_to_position(text: &str, offset: usize) -> Position {
    let offset = clamped_byte_offset(text, offset);
    let mut line = 0_u32;
    let mut line_start = 0_usize;

    for (idx, ch) in text.char_indices() {
        if idx >= offset {
            break;
        }
        advance_position_for_char(ch, idx, &mut line, &mut line_start);
    }

    Position {
        line,
        character: utf16_character_offset(text, line_start, offset),
    }
}

fn clamped_byte_offset(text: &str, offset: usize) -> usize {
    offset.min(text.len())
}

fn advance_position_for_char(ch: char, idx: usize, line: &mut u32, line_start: &mut usize) {
    if ch == '\n' {
        *line = line.saturating_add(1);
        *line_start = idx + ch.len_utf8();
    }
}

fn utf16_character_offset(text: &str, line_start: usize, offset: usize) -> u32 {
    u32::try_from(text[line_start..offset].encode_utf16().count()).unwrap_or(u32::MAX)
}

fn percent_decode_utf8(input: &str) -> std::result::Result<String, ()> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            decoded.push(percent_encoded_byte(bytes, index)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|_| ())
}

fn percent_encoded_byte(bytes: &[u8], index: usize) -> std::result::Result<u8, ()> {
    let hex = bytes.get(index + 1..index + 3).ok_or(())?;
    let hex = std::str::from_utf8(hex).map_err(|_| ())?;
    u8::from_str_radix(hex, 16).map_err(|_| ())
}

fn current_utf8_dir() -> Result<Utf8PathBuf> {
    let path = std::env::current_dir()?;
    Utf8PathBuf::from_path_buf(path).map_err(|path| {
        DieselGuardError::parse_error(format!(
            "Current directory is not valid UTF-8: {}",
            path.display()
        ))
    })
}

fn send_notification<N>(connection: &Connection, params: N::Params) -> Result<()>
where
    N: LspNotification,
{
    connection
        .sender
        .send(Notification::new(N::METHOD.to_string(), params).into())
        .map_err(|err| DieselGuardError::parse_error(err.to_string()))
}

fn publish_diagnostics(connection: &Connection, diagnostics: Vec<DiagnosticEvent>) -> Result<()> {
    for diagnostic in diagnostics {
        let params = PublishDiagnosticsParams::new(
            diagnostic.uri,
            diagnostic.diagnostics,
            diagnostic.version,
        );
        send_notification::<lsp_types::notification::PublishDiagnostics>(connection, params)?;
    }
    Ok(())
}

fn publish_log_messages(connection: &Connection, messages: Vec<MessageEvent>) -> Result<()> {
    for message in messages {
        let params = LogMessageParams {
            typ: message.typ,
            message: message.message,
        };
        send_notification::<lsp_types::notification::LogMessage>(connection, params)?;
    }
    Ok(())
}

fn send_response(connection: &Connection, response: Response) -> Result<()> {
    connection
        .sender
        .send(response.into())
        .map_err(|err| DieselGuardError::parse_error(err.to_string()))
}

fn protocol_error(err: impl std::fmt::Display) -> DieselGuardError {
    DieselGuardError::parse_error(format!("LSP protocol error: {err}"))
}

fn log_message_event(message: impl Into<String>) -> MessageEvent {
    MessageEvent {
        typ: MessageType::LOG,
        message: message.into(),
    }
}

fn show_error_event(message: impl Into<String>) -> MessageEvent {
    MessageEvent {
        typ: MessageType::ERROR,
        message: message.into(),
    }
}

fn deserialize_error_output(method: &str, err: &serde_json::Error) -> HandlerOutput {
    let mut output = HandlerOutput::default();
    output.messages.push(log_message_event(format!(
        "Failed to deserialize {method} notification: {err}"
    )));
    output
}

pub fn unsupported_request_response(id: RequestId, method: &str) -> Response {
    Response {
        id,
        result: None,
        error: Some(ResponseError {
            code: ErrorCode::MethodNotFound as i32,
            message: format!("Unsupported request method: {method}"),
            data: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violation::Violation;
    use lsp_types::{
        ClientCapabilities, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
        DidOpenTextDocumentParams, DidSaveTextDocumentParams, TextDocumentIdentifier,
        TextDocumentItem, VersionedTextDocumentIdentifier,
    };
    use serde_json::Value;
    use serde_json::json;
    use std::str::FromStr;
    use tempfile::tempdir;

    fn uri(value: &str) -> Uri {
        Uri::from_str(value).expect("valid URI")
    }

    fn initialize_params(value: Value) -> InitializeParams {
        serde_json::from_value(value).expect("valid initialize params")
    }

    fn temp_root() -> tempfile::TempDir {
        tempdir().expect("temp dir")
    }

    #[test]
    fn sql_file_uri_filter_accepts_only_file_sql() {
        assert!(is_sql_file_uri(&uri("file:///tmp/migration.sql")));
        assert!(!is_sql_file_uri(&uri("file:///tmp/readme.txt")));
        assert!(!is_sql_file_uri(&uri("untitled:///migration.sql")));
    }

    #[test]
    fn file_uri_to_path_decodes_percent_encoded_paths() {
        let path = file_uri_to_path(&uri("file:///tmp/space%20dir/up.sql")).unwrap();
        assert_eq!(path.as_str(), "/tmp/space dir/up.sql");
    }

    #[test]
    fn file_uri_to_path_accepts_localhost_and_strips_query_fragment() {
        let path = file_uri_to_path(&uri("file://localhost/tmp/up.sql?rev=1#section")).unwrap();
        assert_eq!(path.as_str(), "/tmp/up.sql");
    }

    #[test]
    fn file_uri_to_path_rejects_remote_authority() {
        assert!(file_uri_to_path(&uri("file://db.example/tmp/up.sql")).is_none());
    }

    #[test]
    fn file_uri_to_path_rejects_invalid_percent_encoding() {
        assert!(percent_decode_utf8("/tmp/bad%2.sql").is_err());
        assert!(percent_decode_utf8("/tmp/bad%GG.sql").is_err());
    }

    #[test]
    fn file_uri_to_path_rejects_invalid_utf8_escape() {
        assert!(file_uri_to_path(&uri("file:///tmp/%FF.sql")).is_none());
    }

    #[test]
    fn document_open_change_and_close_update_state() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/open.sql");

        state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: "SELECT 1;".to_string(),
            },
        });
        assert_eq!(state.document(&uri).unwrap().version, Some(1));

        state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 2,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "SELECT 2;".to_string(),
            }],
        });
        assert_eq!(
            state.document(&uri).unwrap().text.as_deref(),
            Some("SELECT 2;")
        );

        let output = state.handle_close(DidCloseTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
        });
        assert!(state.document(&uri).is_none());
        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
    }

    #[test]
    fn closing_sql_document_removes_published_state() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/published.sql");
        state.published_sql_uris.insert(uri.clone());

        let output = state.handle_close(DidCloseTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(!state.published_sql_uris.contains(&uri));
    }

    #[test]
    fn did_change_uses_final_full_sync_change() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/change.sql");

        state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 7,
            },
            content_changes: vec![
                TextDocumentContentChangeEvent {
                    range: None,
                    range_length: None,
                    text: "SELECT 1;".to_string(),
                },
                TextDocumentContentChangeEvent {
                    range: None,
                    range_length: None,
                    text: "SELECT 2;".to_string(),
                },
            ],
        });

        assert_eq!(
            state.document(&uri).unwrap().text.as_deref(),
            Some("SELECT 2;")
        );
        assert_eq!(state.document(&uri).unwrap().version, Some(7));
    }

    #[test]
    fn unchanged_did_change_skips_duplicate_diagnostics() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/unchanged.sql");

        state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: "SELECT 1;".to_string(),
            },
        });
        let output = state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier { uri, version: 1 },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "SELECT 1;".to_string(),
            }],
        });

        assert!(output.diagnostics.is_empty());
    }

    #[test]
    fn violation_diagnostic_mapping_sets_core_fields() {
        let violation = crate::Violation::new(
            "DROP COLUMN",
            "Drops data.",
            "Backfill then ignore the column first.",
        )
        .with_check_name("DropColumnCheck")
        .with_severity(Severity::Warning);
        let diagnostics = violations_to_diagnostics(
            "-- comment\nALTER TABLE users DROP COLUMN email;",
            &vec![(2, violation)],
        );

        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.range.start.line, 1);
        assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::WARNING));
        assert_eq!(
            diagnostic.code,
            Some(NumberOrString::String("DropColumnCheck".to_string()))
        );
        assert_eq!(diagnostic.source.as_deref(), Some(DIAGNOSTIC_SOURCE));
    }

    #[test]
    fn diagnostic_range_uses_utf16_length() {
        let violation = crate::Violation::new("op", "problem", "safe");
        let diagnostics = violations_to_diagnostics(
            "SELECT 1;\nALTER TABLE users ADD COLUMN emoji TEXT DEFAULT '😀';",
            &vec![(2, violation)],
        );
        assert_eq!(
            diagnostics[0].range.end.character,
            u32::try_from(
                "ALTER TABLE users ADD COLUMN emoji TEXT DEFAULT '😀';"
                    .encode_utf16()
                    .count()
            )
            .unwrap()
        );
    }

    #[test]
    fn byte_offset_to_position_tracks_multiline_utf16_offsets() {
        let text = "SELECT 1;\nSELECT '😀';";
        let offset = text.find('😀').unwrap() + '😀'.len_utf8();
        let position = byte_offset_to_position(text, offset);

        assert_eq!(position.line, 1);
        assert_eq!(
            position.character,
            u32::try_from("SELECT '😀".encode_utf16().count()).unwrap()
        );
    }

    #[test]
    fn diagnostic_mapping_omits_empty_check_name() {
        let violation = crate::Violation::new("op", "problem", "");
        let diagnostics = violations_to_diagnostics("SELECT 1;", &vec![(1, violation)]);

        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
        assert!(diagnostics[0].code.is_none());
        assert_eq!(diagnostics[0].message, "problem");
    }

    #[test]
    fn diagnostic_mapping_handles_out_of_range_line() {
        let violation = crate::Violation::new("op", "problem", "safe");
        let diagnostics = violations_to_diagnostics("SELECT 1;", &vec![(99, violation)]);

        assert_eq!(diagnostics[0].range.start.line, 98);
        assert_eq!(diagnostics[0].range.end.character, 0);
    }

    #[test]
    fn apply_output_publishes_diagnostics_before_logs() {
        let (server, client) = Connection::memory();
        let uri = uri("file:///tmp/output.sql");
        let output = HandlerOutput {
            diagnostics: vec![DiagnosticEvent {
                uri: uri.clone(),
                diagnostics: Vec::new(),
                version: Some(4),
            }],
            messages: vec![MessageEvent {
                typ: MessageType::INFO,
                message: "ready".to_string(),
            }],
        };

        ServerState::apply_output(&server, output).unwrap();

        let Message::Notification(first) = client.receiver.try_recv().unwrap() else {
            panic!("expected diagnostics notification");
        };
        assert_eq!(
            first.method,
            lsp_types::notification::PublishDiagnostics::METHOD
        );
        let params: PublishDiagnosticsParams = serde_json::from_value(first.params).unwrap();
        assert_eq!(params.uri, uri);
        assert_eq!(params.version, Some(4));

        let Message::Notification(second) = client.receiver.try_recv().unwrap() else {
            panic!("expected log notification");
        };
        assert_eq!(second.method, lsp_types::notification::LogMessage::METHOD);
        let params: LogMessageParams = serde_json::from_value(second.params).unwrap();
        assert_eq!(params.typ, MessageType::INFO);
        assert_eq!(params.message, "ready");
    }

    #[test]
    fn live_malformed_sql_clears_without_message() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/bad.sql");
        state.track_published_uri(&uri);
        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: "CREATE TABLE @bad;".to_string(),
            },
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert!(!state.published_sql_uris.contains(&uri));
        assert!(output.messages.is_empty());
    }

    #[test]
    fn config_error_clears_and_emits_message() {
        let root = temp_root();
        std::fs::write(root.path().join("diesel-guard.toml"), "check_down = true\n").unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri("file:///tmp/config-error.sql"),
                language_id: "sql".to_string(),
                version: 1,
                text: "SELECT 1;".to_string(),
            },
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.messages[0].typ, MessageType::ERROR);
        assert!(
            output.messages[0]
                .message
                .contains("Missing required field")
        );
    }

    #[test]
    fn repeated_config_error_clears_without_repeating_message() {
        let root = temp_root();
        std::fs::write(root.path().join("diesel-guard.toml"), "check_down = true\n").unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/repeated-config-error.sql");

        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: "SELECT 1;".to_string(),
            },
        });
        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.messages.len(), 1);

        let output = state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier { uri, version: 2 },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "SELECT 2;".to_string(),
            }],
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert!(output.messages.is_empty());
    }

    #[test]
    fn saved_malformed_sql_publishes_parse_diagnostic() {
        let root = temp_root();
        let path = root.path().join("bad.sql");
        std::fs::write(&path, "CREATE TABLE @bad;").unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier {
                uri: uri(&format!("file://{}", path.display())),
            },
            text: None,
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert_eq!(output.diagnostics[0].diagnostics.len(), 1);
        assert_eq!(
            output.diagnostics[0].diagnostics[0].code,
            Some(NumberOrString::String("ParseError".to_string()))
        );
    }

    #[test]
    fn saved_unopened_sql_file_checks_from_disk() {
        let root = temp_root();
        let path = root.path().join("unsafe.sql");
        std::fs::write(
            &path,
            "ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;",
        )
        .unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier {
                uri: uri(&format!("file://{}", path.display())),
            },
            text: None,
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(!output.diagnostics[0].diagnostics.is_empty());
    }

    #[test]
    fn saved_readable_sql_file_prefers_disk_snapshot_over_editor_text() {
        let root = temp_root();
        let path = root.path().join("safe.sql");
        std::fs::write(&path, "SELECT 1;").unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier {
                uri: uri(&format!("file://{}", path.display())),
            },
            text: Some("ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;".to_string()),
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
    }

    #[test]
    fn saved_unreadable_sql_file_falls_back_to_editor_text() {
        let root = temp_root();
        let path = root.path().join("missing.sql");
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier {
                uri: uri(&format!("file://{}", path.display())),
            },
            text: Some("ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;".to_string()),
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(!output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.messages.len(), 1);
        assert_eq!(output.messages[0].typ, MessageType::LOG);
        assert!(
            output.messages[0]
                .message
                .contains("checked in-memory text")
        );
    }

    #[test]
    fn oversized_live_sql_document_skips_diagnostics() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/large.sql");
        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: " ".repeat(MAX_LIVE_DOCUMENT_BYTES + 1),
            },
        });

        assert!(state.document(&uri).unwrap().text.is_none());
        assert!(output.diagnostics.is_empty());
        assert_eq!(output.messages.len(), 1);
        assert!(
            output.messages[0]
                .message
                .contains("Skipping live diagnostics")
        );
    }

    #[test]
    fn live_diagnostics_precheck_clears_non_sql_if_published() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/readme.txt");
        state.track_published_uri(&uri);

        let output = state.run_live_diagnostics(uri, "not sql", Some(8));

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.diagnostics[0].version, Some(8));
    }

    #[test]
    fn non_sql_documents_are_not_tracked() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/readme.md");

        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "markdown".to_string(),
                version: 1,
                text: "# notes".to_string(),
            },
        });

        assert!(output.diagnostics.is_empty());
        assert!(state.document(&uri).is_none());
    }

    #[test]
    fn tracked_sql_documents_are_bounded() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);

        for index in 0..=MAX_TRACKED_DOCUMENTS {
            state.handle_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: uri(&format!("file:///tmp/doc_{index}.sql")),
                    language_id: "sql".to_string(),
                    version: i32::try_from(index).unwrap(),
                    text: "SELECT 1;".to_string(),
                },
            });
        }

        assert_eq!(state.documents.len(), MAX_TRACKED_DOCUMENTS);
    }

    #[test]
    fn incremental_change_document_tracking_is_bounded() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);

        for index in 0..=MAX_TRACKED_DOCUMENTS {
            state.handle_change(DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier {
                    uri: uri(&format!("file:///tmp/incremental_{index}.sql")),
                    version: i32::try_from(index).unwrap(),
                },
                content_changes: vec![TextDocumentContentChangeEvent {
                    range: Some(Range {
                        start: Position {
                            line: 0,
                            character: 0,
                        },
                        end: Position {
                            line: 0,
                            character: 0,
                        },
                    }),
                    range_length: Some(0),
                    text: "SELECT 1;".to_string(),
                }],
            });
        }

        assert_eq!(state.documents.len(), MAX_TRACKED_DOCUMENTS);
    }

    #[test]
    fn published_diagnostic_tracking_is_bounded_and_clears_evictions() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let violations = vec![(
            1,
            Violation::new("unsafe operation", "problem", "safe alternative")
                .with_check_name("TestCheck"),
        )];

        for index in 0..=MAX_PUBLISHED_DIAGNOSTIC_URIS {
            let current_uri = uri(&format!("file:///tmp/published_{index}.sql"));
            let events = state.violations_events(current_uri, "SELECT 1;", &violations, None);
            if index < MAX_PUBLISHED_DIAGNOSTIC_URIS {
                assert_eq!(events.len(), 1);
            } else {
                assert_eq!(events.len(), 2);
                assert!(events[0].diagnostics.is_empty());
                assert_eq!(events[0].uri, uri("file:///tmp/published_0.sql"));
                assert!(!events[1].diagnostics.is_empty());
            }
        }

        assert_eq!(
            state.published_sql_uris.len(),
            MAX_PUBLISHED_DIAGNOSTIC_URIS
        );
        assert!(
            !state
                .published_sql_uris
                .contains(&uri("file:///tmp/published_0.sql"))
        );
        assert!(state.published_sql_uris.contains(&uri(&format!(
            "file:///tmp/published_{MAX_PUBLISHED_DIAGNOSTIC_URIS}.sql"
        ))));
    }

    #[test]
    fn incremental_change_invalidates_saved_text_fallback() {
        let root = temp_root();
        let path = root.path().join("missing.sql");
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri(&format!("file://{}", path.display()));

        state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: "ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;".to_string(),
            },
        });
        assert!(state.document(&uri).unwrap().text.is_some());

        state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 2,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: Some(Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 5,
                    },
                }),
                range_length: Some(5),
                text: "SELECT".to_string(),
            }],
        });
        assert!(state.document(&uri).unwrap().text.is_none());

        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier { uri },
            text: None,
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.messages.len(), 1);
        assert_eq!(output.messages[0].typ, MessageType::ERROR);
        assert!(
            output.messages[0]
                .message
                .contains("Failed to read saved SQL file")
        );
    }

    #[test]
    fn oversized_live_sql_document_does_not_store_fallback_text() {
        let root = temp_root();
        let path = root.path().join("large.sql");
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri(&format!("file://{}", path.display()));

        state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: format!(
                    "{}\nALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;",
                    " ".repeat(MAX_LIVE_DOCUMENT_BYTES + 1)
                ),
            },
        });
        assert!(state.document(&uri).unwrap().text.is_none());

        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier { uri },
            text: None,
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.messages.len(), 1);
        assert_eq!(output.messages[0].typ, MessageType::ERROR);
        assert!(
            output.messages[0]
                .message
                .contains("Failed to read saved SQL file")
        );
    }

    #[test]
    fn oversized_saved_sql_file_skips_diagnostics() {
        let root = temp_root();
        let path = root.path().join("large.sql");
        let oversized_len = usize::try_from(MAX_SAVED_DOCUMENT_BYTES).unwrap() + 1;
        std::fs::write(&path, " ".repeat(oversized_len)).unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri(&format!("file://{}", path.display()));
        state.track_published_uri(&uri);
        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            text: None,
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.messages.len(), 1);
        assert!(
            output.messages[0]
                .message
                .contains("Skipping saved-file diagnostics")
        );
        assert!(!state.published_sql_uris.contains(&uri));
    }

    #[test]
    fn oversized_saved_sql_text_skips_diagnostics() {
        let root = temp_root();
        let path = root.path().join("missing.sql");
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let oversized_len = usize::try_from(MAX_SAVED_DOCUMENT_BYTES).unwrap() + 1;
        let uri = uri(&format!("file://{}", path.display()));
        state.track_published_uri(&uri);
        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            text: Some(" ".repeat(oversized_len)),
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.messages.len(), 1);
        assert!(
            output.messages[0]
                .message
                .contains("Skipping saved-text diagnostics")
        );
        assert!(!state.published_sql_uris.contains(&uri));
    }

    #[test]
    fn config_loading_from_workspace_normalizes_custom_checks_dir() {
        let root = temp_root();
        std::fs::write(
            root.path().join("diesel-guard.toml"),
            "framework = \"diesel\"\ncustom_checks_dir = \"checks\"\n",
        )
        .unwrap();
        let cwd = std::env::current_dir().unwrap();
        let root_path = Utf8Path::from_path(root.path()).unwrap();

        let config = load_lsp_config(root_path).unwrap();

        assert_eq!(std::env::current_dir().unwrap(), cwd);
        assert_eq!(
            config.custom_checks_dir.as_deref(),
            Some(root_path.join("checks").as_str())
        );
    }

    #[test]
    fn lsp_config_loader_rejects_oversized_config() {
        let root = temp_root();
        std::fs::write(
            root.path().join("diesel-guard.toml"),
            format!(
                "framework = \"diesel\"\n# {}\n",
                "x".repeat(usize::try_from(MAX_CONFIG_BYTES).unwrap())
            ),
        )
        .unwrap();
        let root_path = Utf8Path::from_path(root.path()).unwrap();

        let err = load_lsp_config(root_path).unwrap_err();

        assert!(matches!(err, ConfigError::ConfigTooLarge { .. }));
    }

    #[test]
    fn live_diesel_diagnostics_use_metadata_toml() {
        let root = temp_root();
        let migration_dir = root.path().join("2024_01_01_000000_add_idx");
        std::fs::create_dir(&migration_dir).unwrap();
        std::fs::write(
            root.path().join("diesel-guard.toml"),
            "framework = \"diesel\"\nenable_checks = [\"AddIndexCheck\"]\n",
        )
        .unwrap();
        std::fs::write(
            migration_dir.join("metadata.toml"),
            "run_in_transaction = false\n",
        )
        .unwrap();
        let sql_path = migration_dir.join("up.sql");
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);

        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri(&format!("file://{}", sql_path.display())),
                language_id: "sql".to_string(),
                version: 1,
                text: "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);".to_string(),
            },
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
    }

    #[test]
    fn live_sqlx_diagnostics_use_in_memory_no_transaction_directive() {
        let root = temp_root();
        std::fs::write(
            root.path().join("diesel-guard.toml"),
            "framework = \"sqlx\"\nenable_checks = [\"AddIndexCheck\"]\n",
        )
        .unwrap();
        let sql_path = root.path().join("20240101000000_add_idx.sql");
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);

        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri(&format!("file://{}", sql_path.display())),
                language_id: "sql".to_string(),
                version: 1,
                text:
                    "-- no-transaction\nCREATE INDEX CONCURRENTLY idx_users_email ON users(email);"
                        .to_string(),
            },
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
    }

    #[test]
    fn load_from_workspace_without_config_returns_default() {
        let root = temp_root();
        let root_path = Utf8Path::from_path(root.path()).unwrap();
        assert_eq!(
            Config::load_from_dir(root_path).unwrap().framework,
            "diesel"
        );
    }

    #[test]
    fn workspace_root_selection_uses_workspace_folder_then_root_uri_then_cwd() {
        let cwd = Utf8Path::new("/fallback");
        let params = initialize_params(json!({
            "capabilities": {},
            "rootUri": "file:///root-uri",
            "workspaceFolders": [{
                "uri": "file:///workspace-folder",
                "name": "workspace"
            }]
        }));
        assert_eq!(
            select_workspace_root(&params, cwd).as_str(),
            "/workspace-folder"
        );

        let params = initialize_params(json!({
            "capabilities": {},
            "rootUri": "file:///root-uri"
        }));
        assert_eq!(select_workspace_root(&params, cwd).as_str(), "/root-uri");

        let params = InitializeParams {
            capabilities: ClientCapabilities::default(),
            ..initialize_params(json!({ "capabilities": {} }))
        };
        assert_eq!(select_workspace_root(&params, cwd).as_str(), "/fallback");
    }

    #[test]
    fn initialize_capabilities_advertise_full_sync_and_save() {
        let result = initialize_result();
        let Some(TextDocumentSyncCapability::Options(options)) =
            result.capabilities.text_document_sync
        else {
            panic!("expected text sync options");
        };
        assert_eq!(options.open_close, Some(true));
        assert_eq!(options.change, Some(TextDocumentSyncKind::FULL));
        assert!(matches!(
            options.save,
            Some(TextDocumentSyncSaveOptions::SaveOptions(_))
        ));
    }

    #[test]
    fn unsupported_request_uses_method_not_found() {
        let response = unsupported_request_response(RequestId::from(1), "workspace/symbol");
        assert_eq!(
            response.error.unwrap().code,
            ErrorCode::MethodNotFound as i32
        );
    }

    #[test]
    fn run_loop_returns_error_code_when_exit_precedes_shutdown() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let (server, client) = Connection::memory();

        client
            .sender
            .send(Message::Notification(Notification::new(
                lsp_types::notification::Exit::METHOD.to_string(),
                json!(null),
            )))
            .unwrap();

        assert_eq!(state.run_loop(&server).unwrap(), 1);
    }

    #[test]
    fn run_loop_replies_to_unsupported_request_before_exit() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let (server, client) = Connection::memory();

        client
            .sender
            .send(Message::Request(lsp_server::Request::new(
                RequestId::from(7),
                "workspace/symbol".to_string(),
                json!({}),
            )))
            .unwrap();
        client
            .sender
            .send(Message::Notification(Notification::new(
                lsp_types::notification::Exit::METHOD.to_string(),
                json!(null),
            )))
            .unwrap();

        assert_eq!(state.run_loop(&server).unwrap(), 1);
        let Message::Response(response) = client.receiver.try_recv().unwrap() else {
            panic!("expected unsupported request response");
        };
        assert_eq!(
            response.error.unwrap().code,
            ErrorCode::MethodNotFound as i32
        );
    }

    #[test]
    fn run_loop_shutdown_then_exit_returns_success() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let (server, client) = Connection::memory();
        let lsp_server::Connection { sender, receiver } = client;

        sender
            .send(Message::Request(lsp_server::Request::new(
                RequestId::from(9),
                "shutdown".to_string(),
                json!(null),
            )))
            .unwrap();
        sender
            .send(Message::Notification(Notification::new(
                lsp_types::notification::Exit::METHOD.to_string(),
                json!(null),
            )))
            .unwrap();
        drop(sender);

        assert_eq!(state.run_loop(&server).unwrap(), 0);
        let Message::Response(response) = receiver.try_recv().unwrap() else {
            panic!("expected shutdown response");
        };
        assert!(response.error.is_none());
    }

    #[test]
    fn run_loop_ignores_responses_and_returns_zero_when_channel_closes() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let (server, client) = Connection::memory();
        let lsp_server::Connection { sender, .. } = client;

        sender
            .send(Message::Response(Response::new_ok(
                RequestId::from(11),
                json!({"ignored": true}),
            )))
            .unwrap();
        drop(sender);

        assert_eq!(state.run_loop(&server).unwrap(), 0);
    }

    #[test]
    fn handle_notification_dispatches_did_open() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/notify-open.sql");

        let output = state.handle_notification(Notification::new(
            lsp_types::notification::DidOpenTextDocument::METHOD.to_string(),
            json!({
                "textDocument": {
                    "uri": uri.to_string(),
                    "languageId": "sql",
                    "version": 3,
                    "text": "SELECT 1;"
                }
            }),
        ));

        assert!(output.messages.is_empty());
        assert_eq!(state.document(&uri).unwrap().version, Some(3));
    }

    #[test]
    fn document_notification_kind_maps_supported_methods() {
        assert_eq!(
            document_notification_kind(lsp_types::notification::DidOpenTextDocument::METHOD),
            Some(DocumentNotificationKind::Open)
        );
        assert_eq!(
            document_notification_kind(lsp_types::notification::DidChangeTextDocument::METHOD),
            Some(DocumentNotificationKind::Change)
        );
        assert_eq!(
            document_notification_kind(lsp_types::notification::DidSaveTextDocument::METHOD),
            Some(DocumentNotificationKind::Save)
        );
        assert_eq!(
            document_notification_kind(lsp_types::notification::DidCloseTextDocument::METHOD),
            Some(DocumentNotificationKind::Close)
        );
        assert_eq!(document_notification_kind("workspace/unknown"), None);
    }

    #[test]
    fn handle_document_notification_dispatches_change_save_and_close() {
        let root = temp_root();
        let path = root.path().join("notify.sql");
        std::fs::write(&path, "SELECT 1;").unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri(&format!("file://{}", path.display()));

        let change_output = state
            .handle_document_notification(
                lsp_types::notification::DidChangeTextDocument::METHOD,
                json!({
                    "textDocument": { "uri": uri.to_string(), "version": 4 },
                    "contentChanges": [{ "text": "SELECT 2;" }]
                }),
            )
            .unwrap();
        assert!(change_output.messages.is_empty());
        assert_eq!(state.document(&uri).unwrap().version, Some(4));

        let save_output = state
            .handle_document_notification(
                lsp_types::notification::DidSaveTextDocument::METHOD,
                json!({ "textDocument": { "uri": uri.to_string() } }),
            )
            .unwrap();
        assert!(!save_output.diagnostics.is_empty());

        let close_output = state
            .handle_document_notification(
                lsp_types::notification::DidCloseTextDocument::METHOD,
                json!({ "textDocument": { "uri": uri.to_string() } }),
            )
            .unwrap();
        assert!(state.document(&uri).is_none());
        assert_eq!(close_output.diagnostics.len(), 1);
    }

    #[test]
    fn handle_document_notification_returns_none_for_unknown_method() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);

        assert!(
            state
                .handle_document_notification("workspace/didChangeConfiguration", json!({}))
                .is_none()
        );
    }

    #[test]
    fn malformed_supported_notification_emits_deserialize_message() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);

        let output = state.handle_notification(Notification::new(
            lsp_types::notification::DidSaveTextDocument::METHOD.to_string(),
            json!({}),
        ));

        assert_eq!(output.messages.len(), 1);
        assert!(
            output.messages[0]
                .message
                .contains("Failed to deserialize didSave notification")
        );
    }

    #[test]
    fn repeated_unsupported_notifications_do_not_repeat_log() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);

        let first = state.handle_notification(Notification::new(
            "workspace/didChangeConfiguration".to_string(),
            json!({}),
        ));
        assert_eq!(first.messages.len(), 1);
        assert!(
            first.messages[0]
                .message
                .contains("Ignoring unsupported notification")
        );

        let second = state.handle_notification(Notification::new(
            "workspace/didChangeConfiguration".to_string(),
            json!({}),
        ));
        assert!(second.messages.is_empty());
    }

    #[test]
    fn custom_check_warnings_are_collected_for_lsp() {
        let root = temp_root();
        let checks = root.path().join("checks");
        std::fs::create_dir(&checks).unwrap();
        std::fs::write(checks.join("bad.rhai"), "let x = ;").unwrap();
        let config = Config {
            custom_checks_dir: Some(checks.to_str().unwrap().to_string()),
            ..Config::default()
        };
        let (_checker, warnings) = SafetyChecker::with_config_and_warnings(config);

        assert!(!warnings.is_empty());
    }

    #[test]
    fn small_custom_check_signature_changes_when_same_length_content_changes() {
        let root = temp_root();
        let checks = root.path().join("checks");
        std::fs::create_dir(&checks).unwrap();
        let check_path = checks.join("same_len.rhai");
        std::fs::write(&check_path, "return 1;").unwrap();
        let config = Config {
            custom_checks_dir: Some(checks.to_str().unwrap().to_string()),
            ..Config::default()
        };

        let first = custom_checks_signature(&config).unwrap();
        std::fs::write(&check_path, "return 2;").unwrap();
        let second = custom_checks_signature(&config).unwrap();

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].len, second[0].len);
        assert!(first[0].content_hash.is_some());
        assert_ne!(first[0].content_hash, second[0].content_hash);
    }

    #[test]
    fn custom_check_signature_is_sorted_and_ignores_non_files() {
        let root = temp_root();
        let checks = root.path().join("checks");
        std::fs::create_dir(&checks).unwrap();
        std::fs::write(checks.join("zeta.rhai"), "return;").unwrap();
        std::fs::write(checks.join("alpha.rhai"), "return;").unwrap();
        std::fs::write(checks.join("notes.txt"), "return;").unwrap();
        std::fs::create_dir(checks.join("nested.rhai")).unwrap();
        let config = Config {
            custom_checks_dir: Some(checks.to_str().unwrap().to_string()),
            ..Config::default()
        };

        let signature = custom_checks_signature(&config).unwrap();

        let paths: Vec<&str> = signature
            .iter()
            .map(|entry| Utf8Path::new(&entry.path).file_name().unwrap())
            .collect();
        assert_eq!(paths, vec!["alpha.rhai", "zeta.rhai"]);
    }

    #[test]
    fn saved_file_reader_enforces_limit_during_read() {
        let root = temp_root();
        let path = root.path().join("large.sql");
        let oversized_len = usize::try_from(MAX_SAVED_DOCUMENT_BYTES).unwrap() + 1;
        std::fs::write(&path, " ".repeat(oversized_len)).unwrap();
        let path = Utf8Path::from_path(&path).unwrap();

        let result = read_file_to_string_with_limit(path, MAX_SAVED_DOCUMENT_BYTES).unwrap();

        assert!(matches!(result, LimitedFileRead::TooLarge));
    }

    #[test]
    fn saved_file_reader_rejects_non_regular_path() {
        let root = temp_root();
        let path = root.path().join("directory.sql");
        std::fs::create_dir(&path).unwrap();
        let path = Utf8Path::from_path(&path).unwrap();

        let err = read_file_to_string_with_limit(path, MAX_SAVED_DOCUMENT_BYTES).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_reader_rejects_symlinked_sql_file() {
        let root = temp_root();
        let target = root.path().join("target.txt");
        let link = root.path().join("linked.sql");
        std::fs::write(&target, "SELECT 1;").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let path = Utf8Path::from_path(&link).unwrap();

        let err = read_file_to_string_with_limit(path, MAX_SAVED_DOCUMENT_BYTES).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn custom_check_hash_reader_enforces_limit_during_read() {
        let root = temp_root();
        let path = root.path().join("large.rhai");
        let oversized_len = usize::try_from(MAX_CUSTOM_CHECK_SOURCE_BYTES).unwrap() + 1;
        std::fs::write(&path, " ".repeat(oversized_len)).unwrap();

        let err = file_content_hash(&path).unwrap_err();

        assert!(matches!(err, ConfigError::CustomChecksTooLarge { .. }));
    }

    #[test]
    fn saved_parse_diagnostic_is_tracked_and_cleared() {
        let root = temp_root();
        let path = root.path().join("bad.sql");
        std::fs::write(&path, "CREATE TABLE @bad;").unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri(&format!("file://{}", path.display()));

        let output = state.handle_save(DidSaveTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            text: None,
        });
        assert_eq!(output.diagnostics.len(), 1);
        assert_eq!(output.diagnostics[0].diagnostics.len(), 1);
        assert!(state.published_sql_uris.contains(&uri));

        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 2,
                text: " ".repeat(MAX_LIVE_DOCUMENT_BYTES + 1),
            },
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert!(!state.published_sql_uris.contains(&uri));
    }

    #[test]
    fn custom_check_signature_rejects_too_many_rhai_files() {
        let root = temp_root();
        let checks = root.path().join("checks");
        std::fs::create_dir(&checks).unwrap();
        for index in 0..=MAX_LSP_CUSTOM_CHECK_FILES {
            std::fs::write(checks.join(format!("check_{index}.rhai")), "return;").unwrap();
        }
        let config = Config {
            custom_checks_dir: Some(checks.to_str().unwrap().to_string()),
            ..Config::default()
        };

        let err = custom_checks_signature(&config).unwrap_err();

        assert!(matches!(err, ConfigError::CustomChecksTooLarge { .. }));
    }

    #[test]
    fn oversized_custom_check_directory_keeps_builtin_lsp_diagnostics() {
        let root = temp_root();
        let checks = root.path().join("checks");
        std::fs::create_dir(&checks).unwrap();
        for index in 0..=MAX_CUSTOM_CHECK_DIR_ENTRIES {
            std::fs::write(checks.join(format!("note_{index}.txt")), "not a check").unwrap();
        }
        std::fs::write(
            root.path().join("diesel-guard.toml"),
            "framework = \"diesel\"\ncustom_checks_dir = \"checks\"\n",
        )
        .unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);

        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri("file:///tmp/unsafe.sql"),
                language_id: "sql".to_string(),
                version: 1,
                text: "ALTER TABLE users ADD COLUMN admin BOOLEAN DEFAULT FALSE;".to_string(),
            },
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(!output.diagnostics[0].diagnostics.is_empty());
        assert!(output.messages.iter().any(|message| {
            message
                .message
                .contains("Custom checks are disabled for LSP diagnostics")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn custom_check_signature_ignores_symlinked_rhai_file() {
        let root = temp_root();
        let checks = root.path().join("checks");
        std::fs::create_dir(&checks).unwrap();
        let target = checks.join("target.txt");
        let link = checks.join("linked.rhai");
        std::fs::write(&target, "return;").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let config = Config {
            custom_checks_dir: Some(checks.to_str().unwrap().to_string()),
            ..Config::default()
        };

        let signature = custom_checks_signature(&config).unwrap();

        assert!(signature.is_empty());
    }

    #[test]
    fn lsp_checker_cache_refreshes_when_custom_check_changes() {
        let root = temp_root();
        let checks = root.path().join("checks");
        std::fs::create_dir(&checks).unwrap();
        let check_path = checks.join("always_fire.rhai");
        std::fs::write(
            &check_path,
            r#"
            #{
                operation: "custom always fires",
                problem: "custom problem",
                safe_alternative: "custom safe alternative"
            }
            "#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("diesel-guard.toml"),
            "framework = \"diesel\"\ncustom_checks_dir = \"checks\"\n",
        )
        .unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/custom-cache.sql");

        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: "SELECT 1;".to_string(),
            },
        });
        assert_eq!(output.diagnostics.len(), 1);
        assert!(
            output.diagnostics[0]
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("custom problem"))
        );

        std::fs::write(&check_path, "return;").unwrap();

        let output = state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier { uri, version: 2 },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "SELECT 1;".to_string(),
            }],
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
    }

    #[test]
    fn cached_lsp_checker_does_not_replay_custom_check_warnings() {
        let root = temp_root();
        let checks = root.path().join("checks");
        std::fs::create_dir(&checks).unwrap();
        std::fs::write(checks.join("bad.rhai"), "let x = ;").unwrap();
        std::fs::write(
            root.path().join("diesel-guard.toml"),
            "framework = \"diesel\"\ncustom_checks_dir = \"checks\"\n",
        )
        .unwrap();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/warning-cache.sql");

        let output = state.handle_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "sql".to_string(),
                version: 1,
                text: "SELECT 1;".to_string(),
            },
        });
        assert_eq!(output.messages.len(), 1);
        assert!(output.messages[0].message.contains("Compilation error"));

        let output = state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier { uri, version: 2 },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "SELECT 2;".to_string(),
            }],
        });

        assert!(output.messages.is_empty());
    }

    #[test]
    fn incompatible_incremental_change_clears_and_logs() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/incremental.sql");
        state.published_sql_uris.insert(uri.clone());

        let output = state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier { uri, version: 2 },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: Some(Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 1,
                    },
                }),
                range_length: Some(1),
                text: "x".to_string(),
            }],
        });

        assert_eq!(output.diagnostics.len(), 1);
        assert!(output.diagnostics[0].diagnostics.is_empty());
        assert_eq!(output.messages.len(), 1);
    }

    #[test]
    fn repeated_incompatible_incremental_change_does_not_repeat_log() {
        let root = temp_root();
        let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
        let mut state = ServerState::new(root);
        let uri = uri("file:///tmp/repeated-incremental.sql");
        state.published_sql_uris.insert(uri.clone());

        let first = state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 2,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: Some(Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 1,
                    },
                }),
                range_length: Some(1),
                text: "x".to_string(),
            }],
        });
        assert_eq!(first.diagnostics.len(), 1);
        assert_eq!(first.messages.len(), 1);

        state.published_sql_uris.insert(uri.clone());
        let second = state.handle_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier { uri, version: 3 },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: Some(Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 1,
                    },
                }),
                range_length: Some(1),
                text: "y".to_string(),
            }],
        });

        assert_eq!(second.diagnostics.len(), 1);
        assert!(second.messages.is_empty());
    }
}
