//! Command-line option handling

use crate::elf;
use crate::is_bin;
use crate::is_ld;
use crate::is_libc;

use ex::fs;
use ex::io;
use std::path::Path;
use std::path::PathBuf;

use colored::Color;
use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;
use structopt::StructOpt;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("ELF detection error: {}", source))]
    ElfDetectError { source: elf::detect::Error },

    #[snafu(display("failed reading current directory entry: {}", source))]
    DirEntError { source: io::Error },

    #[snafu(display("failed reading current directory: {}", source))]
    ReadDirError { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// automate starting binary exploit challenges
#[derive(StructOpt)]
pub struct Opts {
    /// Binary to pwn
    #[structopt(long)]
    pub bin: Option<PathBuf>,

    /// Challenge libc
    #[structopt(long)]
    pub libc: Option<PathBuf>,

    /// A linker to preload the libc
    #[structopt(long)]
    pub ld: Option<PathBuf>,
}

impl Opts {
    /// Print the locations of known files (binary, libc, linker)
    pub fn print(&self) {
        let f = |opt_path: &Option<PathBuf>, header: &str, color| {
            if let Some(path) = opt_path {
                println!(
                    "{}: {}",
                    header.color(color),
                    path.to_string_lossy().bold().color(color)
                )
            }
        };

        f(&self.bin, "bin", Color::BrightBlue);
        f(&self.libc, "libc", Color::Yellow);
        f(&self.ld, "ld", Color::Green);
    }

    /// For the unspecified files, try to guess their path
    pub fn find_if_unspec(self) -> Result<Self> {
        let mut dir = fs::read_dir(".").context(ReadDirError)?;
        let opts = dir.try_fold(self, Opts::merge_result_entry)?;
        Ok(opts)
    }

    /// Helper for `find_if_unspec()`, merging the `Opts` with a directory entry
    fn merge_result_entry(self, dir_ent: io::Result<fs::DirEntry>) -> Result<Self> {
        self.merge_entry(dir_ent.context(DirEntError)?)
            .context(ElfDetectError)
    }

    /// Helper for `merge_result_entry()`, merging the `Opts` with a directory
    /// entry
    fn merge_entry(self, dir_ent: fs::DirEntry) -> elf::detect::Result<Self> {
        let f = |pred: fn(&Path) -> elf::detect::Result<bool>| {
            let path = dir_ent.path();
            Ok(if pred(&path)? { Some(path) } else { None })
        };

        Ok(Self {
            bin: self.bin.or(f(is_bin)?),
            libc: self.libc.or(f(is_libc)?),
            ld: self.ld.or(f(is_ld)?),
        })
    }
}
