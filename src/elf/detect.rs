use std::io::Read;
use std::path::Path;

use ex::fs::File;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    Open { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Is the binary at `path` an ELF?
pub fn is_elf(path: &Path) -> Result<bool> {
    Ok(File::open(path)
        .context(OpenSnafu)?
        .bytes()
        .take(4)
        .collect::<std::io::Result<Vec<u8>>>()
        .map(|magic| magic == b"\x7fELF")
        .unwrap_or(false))
}
