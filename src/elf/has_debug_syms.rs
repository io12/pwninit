use crate::elf;

use std::path::Path;

use ex::fs;
use snafu::ResultExt;

/// Does the ELF at `path` have debug symbols?
pub fn has_debug_syms(path: &Path) -> elf::parse::Result<bool> {
    let bytes = fs::read(path).context(elf::parse::ReadError)?;
    let elf = elf::parse(path, &bytes)?;
    Ok(elf.section_headers.iter().any(|hdr| {
        elf.shdr_strtab
            .get(hdr.sh_name)
            .map(|s| s.map(|s| s == ".debug_info").unwrap_or(false))
            .unwrap_or(false)
    }))
}
