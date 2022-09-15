use crate::elf;

use std::path::Path;

use ex::fs;
use hex;
use snafu::ResultExt;

/// Get the build id of the given elf file
pub fn get_build_id(path: &Path) -> elf::parse::Result<String> {
    let bytes = fs::read(path).context(elf::parse::ReadSnafu)?;
    let elf = elf::parse(path, &bytes)?;

    let mut iter = elf.iter_note_sections(&bytes, Some(".note.gnu.build-id")).unwrap();
    let section = iter.next().unwrap().context(elf::parse::GoblinSnafu { path })?;

    Ok(hex::encode(section.desc))
}
