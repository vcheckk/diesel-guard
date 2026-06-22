use super::{
    HandlerOutput, ServerState,
    protocol::{
        deserialize_error_output, log_message_event, protocol_error, publish_diagnostics,
        publish_log_messages, send_response,
    },
    session::{document_notification_kind, is_initialized_notification},
};
use crate::error::Result;
use lsp_server::{Connection, ErrorCode, Message, Notification, Response};
use lsp_types::notification::Notification as LspNotification;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LoopControl {
    Continue,
    Exit(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DocumentNotificationKind {
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

impl ServerState {
    pub(super) fn apply_output(connection: &Connection, output: HandlerOutput) -> Result<()> {
        publish_diagnostics(connection, output.diagnostics)?;
        publish_log_messages(connection, output.messages)?;
        Ok(())
    }

    pub(super) fn run_loop(&mut self, connection: &Connection) -> Result<i32> {
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

    pub(super) fn handle_notification(&mut self, notification: Notification) -> HandlerOutput {
        let method = notification.method.as_str();
        if is_initialized_notification(method) {
            return HandlerOutput::default();
        }
        self.handle_document_notification(method, notification.params)
            .unwrap_or_else(|| self.unsupported_notification_output(method))
    }

    pub(super) fn handle_document_notification(
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
