#[cfg(test)]
mod tests {
    use std::str::FromStr;

    #[test]
    fn miri_uri_from_str_drop_passes() {
        let uri = lsp_types::Uri::from_str("file:///tmp/workspace").unwrap();

        drop(uri);
    }

    #[test]
    fn miri_uri_deserialize_drop_fails() {
        let value = serde_json::json!("file:///tmp/workspace");

        let uri: lsp_types::Uri = serde_json::from_value(value).unwrap();

        drop(uri);
    }

    #[test]
    fn miri_initialize_params_workspace_folder_uri_deserialize_drop_fails() {
        let value = serde_json::json!({
            "capabilities": {},
            "workspaceFolders": [{
                "uri": "file:///tmp/workspace",
                "name": "workspace"
            }]
        });

        let params: lsp_types::InitializeParams = serde_json::from_value(value).unwrap();

        drop(params);
    }
}
