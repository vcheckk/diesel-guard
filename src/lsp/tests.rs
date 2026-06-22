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
            text: "-- no-transaction\nCREATE INDEX CONCURRENTLY idx_users_email ON users(email);"
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
    let Some(TextDocumentSyncCapability::Options(options)) = result.capabilities.text_document_sync
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
    let (_checker, warnings) = SafetyChecker::with_config_and_warnings(config).unwrap();

    assert!(!warnings.is_empty());
}

#[test]
fn repeated_check_warnings_are_logged_once() {
    let root = temp_root();
    let root = Utf8Path::from_path(root.path()).unwrap().to_path_buf();
    let mut state = ServerState::new(root);
    let uri = uri("file:///tmp/repeated-warning.sql");
    let first_sql = "-- diesel-guard:disable FakeCheckThatDoesNotExist\nSELECT 1;";
    let second_sql = "-- diesel-guard:disable FakeCheckThatDoesNotExist\nSELECT 2;";

    let first = state.handle_open(DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "sql".to_string(),
            version: 1,
            text: first_sql.to_string(),
        },
    });
    let second = state.handle_change(DidChangeTextDocumentParams {
        text_document: VersionedTextDocumentIdentifier { uri, version: 2 },
        content_changes: vec![TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: second_sql.to_string(),
        }],
    });

    assert_eq!(first.messages.len(), 1);
    assert!(
        first.messages[0]
            .message
            .contains("FakeCheckThatDoesNotExist")
    );
    assert!(second.messages.is_empty());
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
