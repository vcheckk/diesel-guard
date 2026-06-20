use camino::Utf8PathBuf;
use lsp_types::Uri;

pub fn is_sql_file_uri(uri: &Uri) -> bool {
    file_uri_to_path(uri).is_some_and(|path| {
        path.extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
    })
}

pub fn file_uri_to_path(uri: &Uri) -> Option<Utf8PathBuf> {
    let rest = strip_file_uri(uri)?;
    let path = file_uri_local_path(rest)?;
    let path = path_without_query_or_fragment(&path);
    let path = percent_decode_utf8(path).ok()?;
    #[cfg(windows)]
    let path = path.strip_prefix('/').unwrap_or(&path).to_string();

    Some(Utf8PathBuf::from(path))
}

pub(super) fn strip_file_uri(uri: &Uri) -> Option<&str> {
    uri.as_str().strip_prefix("file://")
}

pub(super) fn file_uri_local_path(rest: &str) -> Option<String> {
    if let Some(path) = rest.strip_prefix('/') {
        return Some(format!("/{path}"));
    }

    let slash = rest.find('/')?;
    let authority = &rest[..slash];
    validate_file_uri_authority(authority)?;
    Some(rest[slash..].to_string())
}

pub(super) fn validate_file_uri_authority(authority: &str) -> Option<()> {
    (authority.is_empty() || authority == "localhost").then_some(())
}

pub(super) fn path_without_query_or_fragment(path: &str) -> &str {
    path.split(['?', '#']).next().unwrap_or(path)
}

pub(super) fn percent_decode_utf8(input: &str) -> std::result::Result<String, ()> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            decoded.push(percent_encoded_byte(bytes, index)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|_| ())
}

pub(super) fn percent_encoded_byte(bytes: &[u8], index: usize) -> std::result::Result<u8, ()> {
    let hex = bytes.get(index + 1..index + 3).ok_or(())?;
    let hex = std::str::from_utf8(hex).map_err(|_| ())?;
    u8::from_str_radix(hex, 16).map_err(|_| ())
}
