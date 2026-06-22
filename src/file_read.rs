use std::fs::File;
#[cfg(any(unix, windows))]
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

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

    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt as _;

        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?
    };

    #[cfg(not(any(unix, windows)))]
    let file = File::open(path)?;

    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, context));
    }

    Ok(file)
}
