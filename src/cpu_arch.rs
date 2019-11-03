//! CPU architectures

use crate::Result;

use std::fmt;
use std::io;

use goblin::elf::header::EM_386;
use goblin::elf::header::EM_X86_64;
use goblin::elf::Elf;

/// The CPU architectures supported by `pwninit`
pub enum CpuArch {
    I386,
    Amd64,
}

impl fmt::Display for CpuArch {
    /// Architecture names fitting the spec for Ubuntu repositories
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CpuArch::I386 => "i386",
            CpuArch::Amd64 => "amd64",
        })
    }
}

impl CpuArch {
    /// Detect `CpuArch` from the bytes of an ELF file
    pub fn from_elf_bytes(bytes: &[u8]) -> Result<CpuArch> {
        let elf = Elf::parse(bytes)?;
        let arch = elf.header.e_machine;
        match arch {
            EM_386 => Ok(CpuArch::I386),
            EM_X86_64 => Ok(CpuArch::Amd64),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only x86 is supported by this tool",
            )
            .into()),
        }
    }
}
