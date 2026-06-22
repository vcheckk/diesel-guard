use super::{
    DocumentNotificationKind, SERVER_NAME, ServerState, file_uri_to_path,
    protocol::{current_utf8_dir, protocol_error},
};
use crate::error::{DieselGuardError, Result};
use camino::{Utf8Path, Utf8PathBuf};
use lsp_server::{Connection, IoThreads, RequestId};
use lsp_types::notification::Notification as LspNotification;
use lsp_types::{
    InitializeParams, InitializeResult, SaveOptions, ServerCapabilities, ServerInfo,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions,
    TextDocumentSyncSaveOptions,
};

pub fn run() -> Result<()> {
    let (connection, io_threads) = Connection::stdio();
    run_stdio_session(connection, io_threads)
}

pub(super) fn run_stdio_session(connection: Connection, io_threads: IoThreads) -> Result<()> {
    let exit_code = run_initialized_session(connection)?;
    io_threads.join()?;
    exit_with_code(exit_code);
    Ok(())
}

pub(super) fn run_initialized_session(connection: Connection) -> Result<i32> {
    let root = initialize_connection(&connection)?;
    let exit_code = ServerState::new(root).run_loop(&connection)?;
    drop(connection);
    Ok(exit_code)
}

pub(super) fn initialize_connection(connection: &Connection) -> Result<Utf8PathBuf> {
    let (initialize_id, params) = start_initialize(connection)?;
    let cwd = current_utf8_dir()?;
    let root = select_workspace_root(&params, &cwd);
    finish_initialize(connection, initialize_id)?;
    Ok(root)
}

pub(super) fn start_initialize(connection: &Connection) -> Result<(RequestId, InitializeParams)> {
    let (initialize_id, initialize_params) =
        connection.initialize_start().map_err(protocol_error)?;
    let params = decode_initialize_params(initialize_params)?;
    Ok((initialize_id, params))
}

pub(super) fn decode_initialize_params(value: serde_json::Value) -> Result<InitializeParams> {
    serde_json::from_value(value)
        .map_err(|err| DieselGuardError::parse_error(format!("Invalid initialize params: {err}")))
}

pub(super) fn finish_initialize(connection: &Connection, initialize_id: RequestId) -> Result<()> {
    let result = serde_json::to_value(initialize_result())
        .map_err(|err| DieselGuardError::parse_error(err.to_string()))?;
    connection
        .initialize_finish(initialize_id, result)
        .map_err(protocol_error)
}

pub(super) fn exit_with_code(exit_code: i32) {
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

pub(super) fn is_initialized_notification(method: &str) -> bool {
    method == lsp_types::notification::Initialized::METHOD
}

pub(super) fn document_notification_kind(method: &str) -> Option<DocumentNotificationKind> {
    document_notification_kinds()
        .into_iter()
        .find_map(|(candidate, kind)| (method == candidate).then_some(kind))
}

pub(super) fn document_notification_kinds() -> [(&'static str, DocumentNotificationKind); 4] {
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
