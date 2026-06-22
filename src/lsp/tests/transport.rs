use super::*;

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
