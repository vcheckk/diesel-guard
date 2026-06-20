use crate::config::{Config, ConfigError};
use crate::error::{DieselGuardError, Result};
use crate::scripting::{MAX_CUSTOM_CHECK_DIR_ENTRIES, MAX_CUSTOM_CHECK_SOURCE_BYTES};
use crate::violation::Severity;
use crate::{SafetyChecker, ViolationList};
use camino::{Utf8Path, Utf8PathBuf};
use lsp_server::{
    Connection, ErrorCode, Message, Notification, RequestId, Response, ResponseError,
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
    shutdown_requested: bool,
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

impl ServerState {
    pub fn new(root: Utf8PathBuf) -> Self {
        Self {
            root,
            documents: HashMap::new(),
            published_sql_uris: HashSet::new(),
            published_sql_uri_order: VecDeque::new(),
            checker_cache: None,
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
            self.documents.remove(&uri);
            return self.clear_if_needed(uri, version);
        }

        let Some(text) = final_full_sync_text(&params.content_changes) else {
            self.store_document_state(
                uri.clone(),
                DocumentState {
                    text: None,
                    version,
                },
            );
            let mut output = self.clear_if_needed(uri, version);
            output.messages.push(log_message_event(
                "Received incremental textDocument/didChange despite full-sync capability; diagnostics were cleared.",
            ));
            return output;
        };

        if self
            .documents
            .get(&uri)
            .is_some_and(|doc| doc.text.as_deref() == Some(text) && doc.version == version)
        {
            return HandlerOutput::default();
        }

        self.store_document_state(uri.clone(), live_document_state(text, version));
        self.run_live_diagnostics(uri, text, version)
    }

    pub fn handle_save(&mut self, params: DidSaveTextDocumentParams) -> HandlerOutput {
        let uri = params.text_document.uri;
        if !is_sql_file_uri(&uri) {
            return self.clear_if_needed(uri, None);
        }

        let path = file_uri_to_path(&uri);
        let version = self.documents.get(&uri).and_then(|doc| doc.version);
        let fallback_text = params
            .text
            .or_else(|| self.documents.get(&uri).and_then(|doc| doc.text.clone()));
        let mut output = HandlerOutput::default();

        if let Some(path) = path.as_deref() {
            return self.handle_save_with_file_path(uri, path, version, fallback_text, output);
        }

        let Some(text) = fallback_text else {
            output.diagnostics.push(self.clear_event(uri, version));
            output.messages.push(show_error_event(
                "Saved SQL document has no readable file path or in-memory text.",
            ));
            return output;
        };

        if saved_text_is_too_large(&text) {
            output.diagnostics.push(self.clear_event(uri, version));
            output.messages.push(log_message_event(format!(
                "Skipping saved-text diagnostics for SQL document larger than {MAX_SAVED_DOCUMENT_BYTES} bytes."
            )));
            return output;
        }

        let (checker, warnings) = match self.load_checker() {
            Ok(result) => result,
            Err(err) => return self.config_error_output(uri, version, &err),
        };
        output.push_messages(warnings);
        self.run_saved_text_diagnostics(uri, &text, version, &checker, output)
    }

    fn handle_save_with_file_path(
        &mut self,
        uri: Uri,
        path: &Utf8Path,
        version: Option<i32>,
        mut fallback_text: Option<String>,
        mut output: HandlerOutput,
    ) -> HandlerOutput {
        match read_file_to_string_with_limit(path, MAX_SAVED_DOCUMENT_BYTES) {
            Ok(LimitedFileRead::Text(saved_text)) => {
                self.run_saved_file_diagnostics(uri, path, &saved_text, version, output)
            }
            Ok(LimitedFileRead::TooLarge) => {
                output.diagnostics.push(self.clear_event(uri, version));
                output.messages.push(log_message_event(format!(
                    "Skipping saved-file diagnostics for SQL document larger than {MAX_SAVED_DOCUMENT_BYTES} bytes."
                )));
                output
            }
            Err(err) => {
                let Some(text) = fallback_text.take() else {
                    output.diagnostics.push(self.clear_event(uri, version));
                    output.messages.push(show_error_event(format!(
                        "Failed to read saved SQL file: {err}"
                    )));
                    return output;
                };
                if saved_text_is_too_large(&text) {
                    output.diagnostics.push(self.clear_event(uri, version));
                    output.messages.push(log_message_event(format!(
                        "Skipping saved-text diagnostics for SQL document larger than {MAX_SAVED_DOCUMENT_BYTES} bytes."
                    )));
                    return output;
                }
                let (checker, warnings) = match self.load_checker() {
                    Ok(result) => result,
                    Err(err) => return self.config_error_output(uri, version, &err),
                };
                output.push_messages(warnings);
                output.messages.push(log_message_event(format!(
                    "Saved SQL file was not readable; checked in-memory text without migration metadata: {err}"
                )));
                self.run_saved_text_diagnostics(uri, &text, version, &checker, output)
            }
        }
    }

    fn run_saved_file_diagnostics(
        &mut self,
        uri: Uri,
        path: &Utf8Path,
        saved_text: &str,
        version: Option<i32>,
        mut output: HandlerOutput,
    ) -> HandlerOutput {
        let (checker, warnings) = match self.load_checker() {
            Ok(result) => result,
            Err(err) => return self.config_error_output(uri, version, &err),
        };
        output.push_messages(warnings);
        match checker.check_file_sql_with_warnings(path, saved_text) {
            Ok((violations, check_warnings)) => {
                output.push_messages(check_warnings);
                output.diagnostics.extend(self.violations_events(
                    uri,
                    saved_text,
                    &violations,
                    version,
                ));
            }
            Err(err) if is_parse_error(&err) => {
                output
                    .diagnostics
                    .extend(self.parse_error_diagnostics_events(uri, saved_text, &err, version));
            }
            Err(err) => {
                output.diagnostics.push(self.clear_event(uri, version));
                output.messages.push(show_error_event(format!(
                    "Failed to check saved SQL file: {err}"
                )));
            }
        }
        output
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

        match checker.check_sql_with_warnings(text) {
            Ok((violations, check_warnings)) => {
                output.push_messages(check_warnings);
                output
                    .diagnostics
                    .extend(self.violations_events(uri, text, &violations, version));
            }
            Err(err) if is_parse_error(&err) => {
                output
                    .diagnostics
                    .extend(self.parse_error_diagnostics_events(uri, text, &err, version));
            }
            Err(err) => {
                output.diagnostics.push(self.clear_event(uri, version));
                output.messages.push(show_error_event(format!(
                    "Failed to check saved SQL text: {err}"
                )));
            }
        }
        output
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
        if !is_sql_file_uri(&uri) {
            return self.clear_if_needed(uri, version);
        }

        if text.len() > MAX_LIVE_DOCUMENT_BYTES {
            let mut output = self.clear_if_needed(uri, version);
            output.messages.push(log_message_event(format!(
                "Skipping live diagnostics for SQL document larger than {MAX_LIVE_DOCUMENT_BYTES} bytes; very large live and saved SQL documents are skipped to keep the editor responsive."
            )));
            return output;
        }

        let (checker, warnings) = match self.load_checker() {
            Ok(result) => result,
            Err(err) => return self.config_error_output(uri, version, &err),
        };

        let mut output = HandlerOutput::default();
        output.push_messages(warnings);
        let check_result = file_uri_to_path(&uri).map_or_else(
            || checker.check_sql_with_warnings(text),
            |path| checker.check_file_sql_with_warnings(&path, text),
        );
        match check_result {
            Ok((violations, check_warnings)) => {
                output.push_messages(check_warnings);
                output
                    .diagnostics
                    .extend(self.violations_events(uri, text, &violations, version));
            }
            Err(err) if is_parse_error(&err) => {
                output.diagnostics.push(self.clear_event(uri, version));
            }
            Err(err) => {
                output.diagnostics.push(self.clear_event(uri, version));
                output.messages.push(show_error_event(format!(
                    "Failed to check SQL document: {err}"
                )));
            }
        }
        output
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
        output.messages.push(show_error_event(format!(
            "Failed to load diesel-guard configuration for the workspace: {err}"
        )));
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
        let mut config = load_lsp_config(&self.root)?;
        let mut cache_warnings = Vec::new();
        let key = match checker_cache_key(&config) {
            Ok(key) => key,
            Err(ConfigError::CustomChecksTooLarge { message }) => {
                cache_warnings.push(format!(
                    "Custom checks are disabled for LSP diagnostics: {message}"
                ));
                config.custom_checks_dir = None;
                checker_cache_key(&config)?
            }
            Err(err) => return Err(err),
        };

        if let Some(cache) = self.checker_cache.as_ref().filter(|cache| cache.key == key) {
            return Ok((Arc::clone(&cache.checker), Vec::new()));
        }

        let (checker, mut warnings) = SafetyChecker::with_config_and_warnings(config);
        warnings.splice(0..0, cache_warnings);
        let checker = Arc::new(checker);
        self.checker_cache = Some(CheckerCache {
            key,
            checker: Arc::clone(&checker),
        });
        Ok((checker, warnings))
    }

    fn apply_output(connection: &Connection, output: HandlerOutput) -> Result<()> {
        for diagnostic in output.diagnostics {
            let params = PublishDiagnosticsParams::new(
                diagnostic.uri,
                diagnostic.diagnostics,
                diagnostic.version,
            );
            send_notification::<lsp_types::notification::PublishDiagnostics>(connection, params)?;
        }

        for message in output.messages {
            let params = LogMessageParams {
                typ: message.typ,
                message: message.message,
            };
            send_notification::<lsp_types::notification::LogMessage>(connection, params)?;
        }

        Ok(())
    }

    fn run_loop(&mut self, connection: &Connection) -> Result<i32> {
        for message in &connection.receiver {
            match message {
                Message::Request(request) => {
                    if connection
                        .handle_shutdown(&request)
                        .map_err(protocol_error)?
                    {
                        self.shutdown_requested = true;
                        continue;
                    }
                    send_response(
                        connection,
                        Response::new_err(
                            request.id,
                            ErrorCode::MethodNotFound as i32,
                            format!("Unsupported request method: {}", request.method),
                        ),
                    )?;
                }
                Message::Notification(notification) => {
                    if notification.method == lsp_types::notification::Exit::METHOD {
                        return Ok(i32::from(!self.shutdown_requested));
                    }

                    let output = self.handle_notification(notification);
                    Self::apply_output(connection, output)?;
                }
                Message::Response(_) => {}
            }
        }

        Ok(0)
    }

    fn handle_notification(&mut self, notification: Notification) -> HandlerOutput {
        match notification.method.as_str() {
            lsp_types::notification::Initialized::METHOD => HandlerOutput::default(),
            lsp_types::notification::DidOpenTextDocument::METHOD => {
                match serde_json::from_value(notification.params) {
                    Ok(params) => self.handle_open(params),
                    Err(err) => deserialize_error_output("didOpen", &err),
                }
            }
            lsp_types::notification::DidChangeTextDocument::METHOD => {
                match serde_json::from_value(notification.params) {
                    Ok(params) => self.handle_change(params),
                    Err(err) => deserialize_error_output("didChange", &err),
                }
            }
            lsp_types::notification::DidSaveTextDocument::METHOD => {
                match serde_json::from_value(notification.params) {
                    Ok(params) => self.handle_save(params),
                    Err(err) => deserialize_error_output("didSave", &err),
                }
            }
            lsp_types::notification::DidCloseTextDocument::METHOD => {
                match serde_json::from_value(notification.params) {
                    Ok(params) => self.handle_close(params),
                    Err(err) => deserialize_error_output("didClose", &err),
                }
            }
            other => {
                let mut output = HandlerOutput::default();
                output.messages.push(log_message_event(format!(
                    "Ignoring unsupported notification: {other}"
                )));
                output
            }
        }
    }
}

pub fn run() -> Result<()> {
    let (connection, io_threads) = Connection::stdio();
    let (initialize_id, initialize_params) =
        connection.initialize_start().map_err(protocol_error)?;
    let params = serde_json::from_value::<InitializeParams>(initialize_params).map_err(|err| {
        DieselGuardError::parse_error(format!("Invalid initialize params: {err}"))
    })?;
    let cwd = current_utf8_dir()?;
    let root = select_workspace_root(&params, &cwd);
    let initialize_result = initialize_result();
    connection
        .initialize_finish(
            initialize_id,
            serde_json::to_value(initialize_result)
                .map_err(|err| DieselGuardError::parse_error(err.to_string()))?,
        )
        .map_err(protocol_error)?;

    let exit_code = ServerState::new(root).run_loop(&connection)?;
    drop(connection);
    io_threads.join()?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
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

fn checker_cache_key(config: &Config) -> std::result::Result<CheckerCacheKey, ConfigError> {
    Ok(CheckerCacheKey {
        config: format!("{config:?}"),
        custom_checks_signature: custom_checks_signature(config)?,
    })
}

fn custom_checks_signature(
    config: &Config,
) -> std::result::Result<Vec<CustomCheckFileSignature>, ConfigError> {
    let Some(custom_checks_dir) = config.custom_checks_dir.as_deref() else {
        return Ok(Vec::new());
    };

    let Ok(entries) = std::fs::read_dir(Utf8Path::new(custom_checks_dir)) else {
        return Ok(Vec::new());
    };

    let mut signature = Vec::new();
    let mut total_hash_bytes = 0_u64;

    for (index, entry) in entries.enumerate() {
        if index >= MAX_CUSTOM_CHECK_DIR_ENTRIES {
            return Err(custom_checks_too_large(format!(
                "more than {MAX_CUSTOM_CHECK_DIR_ENTRIES} directory entries in {custom_checks_dir}"
            )));
        }

        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "rhai") {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }

        if signature.len() >= MAX_LSP_CUSTOM_CHECK_FILES {
            return Err(custom_checks_too_large(format!(
                "more than {MAX_LSP_CUSTOM_CHECK_FILES} .rhai custom check files in {custom_checks_dir}"
            )));
        }

        let file_signature = custom_check_file_signature(&path, &mut total_hash_bytes)?;
        signature.push(file_signature);
    }

    signature.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(signature)
}

fn custom_check_file_signature(
    path: &std::path::Path,
    total_hash_bytes: &mut u64,
) -> std::result::Result<CustomCheckFileSignature, ConfigError> {
    let metadata = std::fs::metadata(path).ok();
    let len = metadata.as_ref().map(std::fs::Metadata::len);
    let content_hash = if len.is_some_and(|len| len <= MAX_CUSTOM_CHECK_SOURCE_BYTES) {
        let Some((hash, bytes_read)) = file_content_hash(path)? else {
            return Ok(CustomCheckFileSignature {
                path: path.display().to_string(),
                modified: metadata
                    .as_ref()
                    .and_then(|metadata| metadata.modified().ok()),
                len,
                content_hash: None,
            });
        };
        let next_total = total_hash_bytes.saturating_add(bytes_read);
        if next_total > MAX_LSP_CUSTOM_CHECK_TOTAL_SOURCE_BYTES {
            return Err(custom_checks_too_large(format!(
                "more than {MAX_LSP_CUSTOM_CHECK_TOTAL_SOURCE_BYTES} bytes of custom check content would be hashed"
            )));
        }
        *total_hash_bytes = next_total;
        Some(hash)
    } else {
        None
    };

    Ok(CustomCheckFileSignature {
        path: path.display().to_string(),
        modified: metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok()),
        len,
        content_hash,
    })
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
    let file_type = std::fs::symlink_metadata(path)?.file_type();
    if !file_type.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    let file = std::fs::File::open(path)?;
    let mut reader = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
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
    let raw = uri.as_str();
    let rest = raw.strip_prefix("file://")?;
    let path = if let Some(path) = rest.strip_prefix('/') {
        format!("/{path}")
    } else {
        let slash = rest.find('/')?;
        let authority = &rest[..slash];
        if !authority.is_empty() && authority != "localhost" {
            return None;
        }
        rest[slash..].to_string()
    };
    let path = path
        .split(['?', '#'])
        .next()
        .map(percent_decode_utf8)
        .and_then(std::result::Result::ok)?;

    #[cfg(windows)]
    let path = path.strip_prefix('/').unwrap_or(&path).to_string();

    Some(Utf8PathBuf::from(path))
}

pub fn violations_to_diagnostics(text: &str, violations: &ViolationList) -> Vec<Diagnostic> {
    let lines = text.lines().collect::<Vec<_>>();
    violations
        .iter()
        .map(|(line, violation)| {
            let zero_indexed_line = u32::try_from(line.saturating_sub(1)).unwrap_or(u32::MAX);
            let line_text = lines
                .get(line.saturating_sub(1))
                .copied()
                .unwrap_or_default();
            let severity = match violation.severity {
                Severity::Error => DiagnosticSeverity::ERROR,
                Severity::Warning => DiagnosticSeverity::WARNING,
            };
            let code = (!violation.check_name.is_empty())
                .then(|| NumberOrString::String(violation.check_name.clone()));
            Diagnostic::new(
                line_range(zero_indexed_line, line_text),
                Some(severity),
                code,
                Some(DIAGNOSTIC_SOURCE.to_string()),
                diagnostic_message(&violation.problem, &violation.safe_alternative),
                None,
                None,
            )
        })
        .collect()
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
    let offset = offset.min(text.len());
    let mut line = 0_u32;
    let mut line_start = 0_usize;

    for (idx, ch) in text.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line = line.saturating_add(1);
            line_start = idx + ch.len_utf8();
        }
    }

    Position {
        line,
        character: u32::try_from(text[line_start..offset].encode_utf16().count())
            .unwrap_or(u32::MAX),
    }
}

fn percent_decode_utf8(input: &str) -> std::result::Result<String, ()> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(hex) = bytes.get(index + 1..index + 3) else {
                return Err(());
            };
            let hex = std::str::from_utf8(hex).map_err(|_| ())?;
            decoded.push(u8::from_str_radix(hex, 16).map_err(|_| ())?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|_| ())
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
}
