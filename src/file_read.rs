macro_rules! open_regular_file {
    ($path:expr, $context:expr $(,)?) => {{
        || -> std::io::Result<std::fs::File> {
            let path = $path;
            let context = $context;
            let file_type = std::fs::symlink_metadata(path)?.file_type();
            if !file_type.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    context,
                ));
            }

            #[cfg(unix)]
            let file = {
                use std::os::unix::fs::OpenOptionsExt as _;

                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(path)?
            };

            #[cfg(not(unix))]
            let file = std::fs::File::open(path)?;

            if !file.metadata()?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    context,
                ));
            }
            Ok(file)
        }()
    }};
}

pub(crate) use open_regular_file;
