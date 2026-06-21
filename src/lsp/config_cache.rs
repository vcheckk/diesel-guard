use super::{
    CheckerCacheKey, CustomCheckFileSignature, DocumentState, LimitedFileRead, MAX_CONFIG_BYTES,
    MAX_LIVE_DOCUMENT_BYTES, MAX_LSP_CUSTOM_CHECK_FILES, MAX_LSP_CUSTOM_CHECK_TOTAL_SOURCE_BYTES,
    MAX_SAVED_DOCUMENT_BYTES,
};
use crate::config::{Config, ConfigError};
use crate::scripting::{MAX_CUSTOM_CHECK_DIR_ENTRIES, MAX_CUSTOM_CHECK_SOURCE_BYTES};
use camino::Utf8Path;
use std::hash::{Hash, Hasher};
use std::io::Read;

pub fn load_lsp_config(root: &Utf8Path) -> std::result::Result<Config, ConfigError> {
    let mut config = Config::load_from_dir_with_limit(root, MAX_CONFIG_BYTES)?;
    if let Some(custom_checks_dir) = config.custom_checks_dir.as_deref() {
        let path = Utf8Path::new(custom_checks_dir);
        if path.is_relative() {
            config.custom_checks_dir = Some(root.join(path).to_string());
        }
    }
    Ok(config)
}

pub(super) fn live_document_state(text: &str, version: Option<i32>) -> DocumentState {
    DocumentState {
        text: (text.len() <= MAX_LIVE_DOCUMENT_BYTES).then(|| text.to_string()),
        version,
    }
}

pub(super) fn saved_text_is_too_large(text: &str) -> bool {
    text.len() > usize::try_from(MAX_SAVED_DOCUMENT_BYTES).unwrap_or(usize::MAX)
}

pub(super) fn live_text_is_too_large(text: &str) -> bool {
    text.len() > MAX_LIVE_DOCUMENT_BYTES
}

pub(super) fn checker_cache_key(
    config: &Config,
) -> std::result::Result<CheckerCacheKey, ConfigError> {
    Ok(CheckerCacheKey {
        config: format!("{config:?}"),
        custom_checks_signature: custom_checks_signature(config)?,
    })
}

pub(super) fn checker_cache_key_with_lsp_fallback(
    config: &mut Config,
    cache_warnings: &mut Vec<String>,
) -> std::result::Result<CheckerCacheKey, ConfigError> {
    match checker_cache_key(config) {
        Ok(key) => Ok(key),
        Err(ConfigError::CustomChecksTooLarge { message }) => {
            cache_warnings.push(format!(
                "Custom checks are disabled for LSP diagnostics: {message}"
            ));
            config.custom_checks_dir = None;
            checker_cache_key(config)
        }
        Err(err) => Err(err),
    }
}

pub(super) fn custom_checks_signature(
    config: &Config,
) -> std::result::Result<Vec<CustomCheckFileSignature>, ConfigError> {
    let Some((custom_checks_dir, entries)) = custom_check_signature_entries(config) else {
        return Ok(Vec::new());
    };
    collect_custom_checks_signature(custom_checks_dir, entries)
}

pub(super) fn custom_check_signature_entries(config: &Config) -> Option<(&str, std::fs::ReadDir)> {
    let custom_checks_dir = config.custom_checks_dir.as_deref()?;
    let Ok(entries) = std::fs::read_dir(Utf8Path::new(custom_checks_dir)) else {
        return None;
    };
    Some((custom_checks_dir, entries))
}

pub(super) fn collect_custom_checks_signature(
    custom_checks_dir: &str,
    entries: std::fs::ReadDir,
) -> std::result::Result<Vec<CustomCheckFileSignature>, ConfigError> {
    let mut signature = Vec::new();
    let mut total_hash_bytes = 0_u64;

    for (index, entry) in entries.enumerate() {
        enforce_custom_check_entry_limit(index, custom_checks_dir)?;

        let Some(path) = lsp_custom_check_file_path(entry) else {
            continue;
        };
        enforce_custom_check_file_limit(&signature, custom_checks_dir)?;

        let file_signature = custom_check_file_signature(&path, &mut total_hash_bytes)?;
        signature.push(file_signature);
    }

    signature.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(signature)
}

pub(super) fn enforce_custom_check_entry_limit(
    index: usize,
    custom_checks_dir: &str,
) -> std::result::Result<(), ConfigError> {
    if index >= MAX_CUSTOM_CHECK_DIR_ENTRIES {
        return Err(custom_checks_too_large(format!(
            "more than {MAX_CUSTOM_CHECK_DIR_ENTRIES} directory entries in {custom_checks_dir}"
        )));
    }
    Ok(())
}

pub(super) fn lsp_custom_check_file_path(
    entry: std::io::Result<std::fs::DirEntry>,
) -> Option<std::path::PathBuf> {
    let entry = entry.ok()?;
    let path = entry.path();
    if path.extension().is_none_or(|extension| extension != "rhai") {
        return None;
    }
    if !entry.file_type().ok()?.is_file() {
        return None;
    }
    Some(path)
}

pub(super) fn enforce_custom_check_file_limit(
    signature: &[CustomCheckFileSignature],
    custom_checks_dir: &str,
) -> std::result::Result<(), ConfigError> {
    if signature.len() >= MAX_LSP_CUSTOM_CHECK_FILES {
        return Err(custom_checks_too_large(format!(
            "more than {MAX_LSP_CUSTOM_CHECK_FILES} .rhai custom check files in {custom_checks_dir}"
        )));
    }
    Ok(())
}

pub(super) fn custom_check_file_signature(
    path: &std::path::Path,
    total_hash_bytes: &mut u64,
) -> std::result::Result<CustomCheckFileSignature, ConfigError> {
    let metadata = std::fs::metadata(path).ok();
    let len = metadata.as_ref().map(std::fs::Metadata::len);
    let content_hash = custom_check_signature_hash(path, len, total_hash_bytes)?;
    Ok(custom_check_signature_from_parts(
        path,
        metadata.as_ref(),
        len,
        content_hash,
    ))
}

pub(super) fn custom_check_signature_hash(
    path: &std::path::Path,
    len: Option<u64>,
    total_hash_bytes: &mut u64,
) -> std::result::Result<Option<u64>, ConfigError> {
    if len.is_none_or(|len| len > MAX_CUSTOM_CHECK_SOURCE_BYTES) {
        return Ok(None);
    }

    let Some((hash, bytes_read)) = file_content_hash(path)? else {
        return Ok(None);
    };
    enforce_lsp_custom_check_hash_budget(total_hash_bytes, bytes_read)?;
    Ok(Some(hash))
}

pub(super) fn enforce_lsp_custom_check_hash_budget(
    total_hash_bytes: &mut u64,
    bytes_read: u64,
) -> std::result::Result<(), ConfigError> {
    let next_total = total_hash_bytes.saturating_add(bytes_read);
    if next_total > MAX_LSP_CUSTOM_CHECK_TOTAL_SOURCE_BYTES {
        return Err(custom_checks_too_large(format!(
            "more than {MAX_LSP_CUSTOM_CHECK_TOTAL_SOURCE_BYTES} bytes of custom check content would be hashed"
        )));
    }
    *total_hash_bytes = next_total;
    Ok(())
}

pub(super) fn custom_check_signature_from_parts(
    path: &std::path::Path,
    metadata: Option<&std::fs::Metadata>,
    len: Option<u64>,
    content_hash: Option<u64>,
) -> CustomCheckFileSignature {
    CustomCheckFileSignature {
        path: path.display().to_string(),
        modified: metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok()),
        len,
        content_hash,
    }
}

pub(super) fn file_content_hash(
    path: &std::path::Path,
) -> std::result::Result<Option<(u64, u64)>, ConfigError> {
    let Ok(file) =
        crate::file_read::open_regular_file(path, "custom check path is not a regular file")
    else {
        return Ok(None);
    };
    let mut reader = file.take(MAX_CUSTOM_CHECK_SOURCE_BYTES.saturating_add(1));
    let mut bytes = Vec::new();
    if reader.read_to_end(&mut bytes).is_err() {
        return Ok(None);
    }
    let bytes_read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if bytes_read > MAX_CUSTOM_CHECK_SOURCE_BYTES {
        return Err(custom_checks_too_large(format!(
            "custom check file grew beyond {MAX_CUSTOM_CHECK_SOURCE_BYTES} bytes while hashing: {}",
            path.display()
        )));
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    Ok(Some((hasher.finish(), bytes_read)))
}

pub(super) fn custom_checks_too_large(message: String) -> ConfigError {
    ConfigError::CustomChecksTooLarge { message }
}

pub(super) fn read_file_to_string_with_limit(
    path: &Utf8Path,
    limit: u64,
) -> std::io::Result<LimitedFileRead> {
    let bytes = read_file_bytes_with_limit(path, limit)?;
    limited_bytes_to_string(bytes, limit)
}

pub(super) fn read_file_bytes_with_limit(path: &Utf8Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let file =
        crate::file_read::open_regular_file(path.as_std_path(), "path is not a regular file")?;
    let mut reader = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn limited_bytes_to_string(
    bytes: Vec<u8>,
    limit: u64,
) -> std::io::Result<LimitedFileRead> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Ok(LimitedFileRead::TooLarge);
    }
    String::from_utf8(bytes)
        .map(LimitedFileRead::Text)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}
