use super::*;

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
