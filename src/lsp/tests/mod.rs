use super::*;
use crate::scripting::{MAX_CUSTOM_CHECK_DIR_ENTRIES, MAX_CUSTOM_CHECK_SOURCE_BYTES};
use crate::violation::Severity;
use crate::violation::Violation;
use camino::Utf8Path;
use lsp_server::{ErrorCode, RequestId};
use lsp_types::{
    ClientCapabilities, DiagnosticSeverity, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    InitializeParams, LogMessageParams, NumberOrString, Position, PublishDiagnosticsParams, Range,
    TextDocumentContentChangeEvent, TextDocumentIdentifier, TextDocumentItem,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncSaveOptions,
    VersionedTextDocumentIdentifier,
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

mod config;
mod custom_checks;
mod diagnostics;
mod documents;
mod live_save;
mod transport;
mod uri;
