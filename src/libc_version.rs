use crate::cpu_arch::CpuArch;
use crate::Result;

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use twoway::find_bytes;

pub struct LibcVersion {
    pub string: String,
    pub string_short: String,
    pub arch: CpuArch,
}

impl fmt::Display for LibcVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.string, self.arch)
    }
}

impl LibcVersion {
    fn error() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "failed to determine libc version (note that this only works on ubuntu glibc)",
        )
    }

    pub fn detect(libc: &Path) -> Result<Self> {
        let bytes = fs::read(libc)?;
        let string = Self::version_string_from_bytes(&bytes)?;
        let string_short = string
            .split('-')
            .next()
            .ok_or_else(Self::error)?
            .to_string();

        Ok(Self {
            string,
            string_short,
            arch: CpuArch::from_elf_bytes(&bytes)?,
        })
    }

    fn version_string_from_bytes(libc: &[u8]) -> Result<String> {
        let split = b"GNU C Library (Ubuntu GLIBC ";
        let pos = find_bytes(&libc, split).ok_or_else(LibcVersion::error)?;
        let ver_str = &libc[pos + split.len()..];
        let pos = ver_str
            .iter()
            .position(|&c| c == b')')
            .ok_or_else(LibcVersion::error)?;
        let ver_str = &ver_str[..pos];
        let ver_str = std::str::from_utf8(ver_str)?.to_string();
        Ok(ver_str)
    }
}
