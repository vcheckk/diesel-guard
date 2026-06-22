use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

pub(crate) fn open_regular_file(path: &Path, context: &'static str) -> io::Result<File> {
    let file_type = std::fs::symlink_metadata(path)?.file_type();
    if !file_type.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, context));
    }

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt as _;

        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?
    };

    #[cfg(not(unix))]
    let file = File::open(path)?;

    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, context));
    }

    Ok(file)
}

pub(crate) fn read_regular_file_bytes_with_limit(
    path: &Path,
    limit: u64,
    context: &'static str,
) -> io::Result<Vec<u8>> {
    let file = open_regular_file(path, context)?;
    let mut reader = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}
