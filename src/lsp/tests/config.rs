use super::*;

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
fn load_from_workspace_without_config_returns_default() {
    let root = temp_root();
    let root_path = Utf8Path::from_path(root.path()).unwrap();
    assert_eq!(
        Config::load_from_dir(root_path).unwrap().framework,
        "diesel"
    );
}
