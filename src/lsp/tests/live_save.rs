use super::*;

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
