use super::{
    DIAGNOSTIC_SOURCE, DiagnosticEvent, HandlerOutput, MAX_PUBLISHED_DIAGNOSTIC_URIS, ServerState,
    diagnostics::{empty_event, is_parse_error, parse_error_event, violations_to_diagnostics},
    protocol::show_error_event,
};
use crate::ViolationList;
use crate::config::ConfigError;
use crate::error::{DieselGuardError, Result};
use lsp_types::Uri;

#[derive(Clone, Copy)]
pub(super) enum ParseErrorOutput {
    PublishDiagnostic,
    ClearOnly,
}

pub(super) struct CheckDiagnosticContext<'a> {
    pub(super) uri: Uri,
    pub(super) version: Option<i32>,
    pub(super) parse_error_output: ParseErrorOutput,
    pub(super) error_context: &'a str,
}

impl ServerState {
    pub(super) fn apply_check_result(
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

    pub(super) fn clear_if_needed(&mut self, uri: Uri, version: Option<i32>) -> HandlerOutput {
        if self.untrack_published_uri(&uri) {
            HandlerOutput::with_diagnostic(empty_event(uri, version))
        } else {
            HandlerOutput::default()
        }
    }

    pub(super) fn config_error_output(
        &mut self,
        uri: Uri,
        version: Option<i32>,
        err: &ConfigError,
    ) -> HandlerOutput {
        let mut output = HandlerOutput::with_diagnostic(self.clear_event(uri, version));
        let message =
            format!("Failed to load {DIAGNOSTIC_SOURCE} configuration for the workspace: {err}");
        if self.last_config_error_message.as_deref() != Some(message.as_str()) {
            self.last_config_error_message = Some(message.clone());
            output.messages.push(show_error_event(message));
        }
        output
    }

    pub(super) fn clear_event(&mut self, uri: Uri, version: Option<i32>) -> DiagnosticEvent {
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

    pub(super) fn violations_events(
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

    pub(super) fn track_published_uri(&mut self, uri: &Uri) -> Vec<DiagnosticEvent> {
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

    pub(super) fn untrack_published_uri(&mut self, uri: &Uri) -> bool {
        let removed = self.published_sql_uris.remove(uri);
        if removed {
            self.published_sql_uri_order
                .retain(|tracked_uri| tracked_uri != uri);
        }
        removed
    }
}
