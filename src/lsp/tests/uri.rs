use super::*;

#[test]
fn sql_file_uri_filter_accepts_only_file_sql() {
    assert!(is_sql_file_uri(&uri("file:///tmp/migration.sql")));
    assert!(is_sql_file_uri(&uri("file://db.example/tmp/migration.sql")));
    assert!(!is_sql_file_uri(&uri("file:///tmp/readme.txt")));
    assert!(!is_sql_file_uri(&uri("file:///tmp/%FF.sql")));
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
