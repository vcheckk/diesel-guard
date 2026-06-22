use super::{DiagnosticEvent, HandlerOutput, MessageEvent};
use crate::error::{DieselGuardError, Result};
use camino::Utf8PathBuf;
use lsp_server::{Connection, ErrorCode, Notification, RequestId, Response, ResponseError};
use lsp_types::notification::Notification as LspNotification;
use lsp_types::{LogMessageParams, MessageType, PublishDiagnosticsParams};

pub(super) fn current_utf8_dir() -> Result<Utf8PathBuf> {
    let path = std::env::current_dir()?;
    Utf8PathBuf::from_path_buf(path).map_err(|path| {
        DieselGuardError::parse_error(format!(
            "Current directory is not valid UTF-8: {}",
            path.display()
        ))
    })
}

pub(super) fn send_notification<N>(connection: &Connection, params: N::Params) -> Result<()>
where
    N: LspNotification,
{
    connection
        .sender
        .send(Notification::new(N::METHOD.to_string(), params).into())
        .map_err(|err| DieselGuardError::parse_error(err.to_string()))
}

pub(super) fn publish_diagnostics(
    connection: &Connection,
    diagnostics: Vec<DiagnosticEvent>,
) -> Result<()> {
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

pub(super) fn publish_log_messages(
    connection: &Connection,
    messages: Vec<MessageEvent>,
) -> Result<()> {
    for message in messages {
        let params = LogMessageParams {
            typ: message.typ,
            message: message.message,
        };
        send_notification::<lsp_types::notification::LogMessage>(connection, params)?;
    }
    Ok(())
}

pub(super) fn send_response(connection: &Connection, response: Response) -> Result<()> {
    connection
        .sender
        .send(response.into())
        .map_err(|err| DieselGuardError::parse_error(err.to_string()))
}

pub(super) fn protocol_error(err: impl std::fmt::Display) -> DieselGuardError {
    DieselGuardError::parse_error(format!("LSP protocol error: {err}"))
}

pub(super) fn log_message_event(message: impl Into<String>) -> MessageEvent {
    MessageEvent {
        typ: MessageType::LOG,
        message: message.into(),
    }
}

pub(super) fn show_error_event(message: impl Into<String>) -> MessageEvent {
    MessageEvent {
        typ: MessageType::ERROR,
        message: message.into(),
    }
}

pub(super) fn deserialize_error_output(method: &str, err: &serde_json::Error) -> HandlerOutput {
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
