//! Libc version operations

use crate::cpu_arch;
use crate::cpu_arch::CpuArch;

use std::fmt;
use std::path::Path;
use std::str;

use ex::fs;
use ex::io;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;
use twoway::find_bytes;

/// Libc version information
pub struct LibcVersion {
    /// Long string representation of a libc version
    ///
    /// Example: `"2.23-0ubuntu10"`
    pub string: String,

    /// Short string representation of a libc version
    ///
    /// Example: `"2.23"`
    pub string_short: String,

    /// Architecture of libc
    pub arch: CpuArch,
}

impl fmt::Display for LibcVersion {
    /// Write libc version in format used by Ubuntu repositories
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.string, self.arch)
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed reading file: {}", source))]
    ReadError { source: io::Error },

    #[snafu(display("failed finding version string"))]
    NotFoundError,

    #[snafu(display("invalid architecture: {}", source))]
    ArchError { source: cpu_arch::Error },

    #[snafu(display("invalid UTF-8 in version string: {}", source))]
    Utf8Error { source: str::Utf8Error },
}

pub type Result<T> = std::result::Result<T, Error>;

impl LibcVersion {
    /// Detect the version of a libc
    pub fn detect(libc: &Path) -> Result<Self> {
        let bytes = fs::read(libc).context(ReadError)?;
        let string = Self::version_string_from_bytes(&bytes)?;
        let string_short = string.split('-').next().context(NotFoundError)?.to_string();

        Ok(Self {
            string,
            string_short,
            arch: CpuArch::from_elf_bytes(libc, &bytes).context(ArchError)?,
        })
    }

    /// Extract the long version string from the bytes of a libc
    fn version_string_from_bytes(libc: &[u8]) -> Result<String> {
        let split: [&[u8]; 2] = [
            b"GNU C Library (Ubuntu GLIBC ",
            b"GNU C Library (Ubuntu EGLIBC ",
        ];
        let pos = split
            .iter()
            .find_map(|cut| {
                let pos = find_bytes(&libc, cut);
                Some(pos? + cut.len())
            })
            .context(NotFoundError)?;
        let ver_str = &libc[pos..];
        let pos = ver_str
            .iter()
            .position(|&c| c == b')')
            .context(NotFoundError)?;
        let ver_str = &ver_str[..pos];
        let ver_str = std::str::from_utf8(ver_str).context(Utf8Error)?.to_string();
        Ok(ver_str)
    }
}
