use super::*;

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
