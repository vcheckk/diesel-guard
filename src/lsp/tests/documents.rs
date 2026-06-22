use super::*;

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
