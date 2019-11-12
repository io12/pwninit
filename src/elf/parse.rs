use std::path::Path;
use std::path::PathBuf;

use ex::io;
use goblin::elf::Elf;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    ReadError {
        source: io::Error,
    },
    GoblinError {
        path: PathBuf,
        source: goblin::error::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn parse<'a>(path: &Path, bytes: &'a [u8]) -> Result<Elf<'a>> {
    Elf::parse(bytes).context(GoblinError { path })
}
