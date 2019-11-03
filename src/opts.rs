//! Command-line option handling

use crate::util;
use crate::Result;

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use colored::Color;
use colored::Colorize;
use structopt::StructOpt;

/// Command-line options
#[derive(StructOpt)]
pub struct Opts {
    /// Working directory
    #[structopt(long, default_value = ".")]
    dir: PathBuf,

    /// Binary to pwn
    #[structopt(long)]
    bin: Option<PathBuf>,

    /// Challenge libc
    #[structopt(long)]
    libc: Option<PathBuf>,

    /// An ld-linux.so to load libc
    #[structopt(long)]
    ld: Option<PathBuf>,
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
        let dir = fs::read_dir(&self.dir)?;
        let opts = dir.fold(self, Opts::merge_result_entry);
        Ok(opts)
    }

    /// Helper for `find_if_unspec()`, merging the `Opts` with a directory entry
    fn merge_result_entry(self, dir_ent: io::Result<fs::DirEntry>) -> Self {
        match dir_ent {
            Ok(ent) => self.merge_entry(ent),
            Err(_) => self,
        }
    }

    /// Helper for `merge_result_entry()`, merging the `Opts` with a directory
    /// entry
    fn merge_entry(self, dir_ent: fs::DirEntry) -> Self {
        let f = |pred: fn(&Path) -> bool| {
            let path = dir_ent.path();
            if pred(&path) {
                Some(path)
            } else {
                None
            }
        };

        Self {
            dir: self.dir,
            bin: self.bin.or_else(|| f(util::is_bin)),
            libc: self.libc.or_else(|| f(util::is_libc)),
            ld: self.ld.or_else(|| f(util::is_ld)),
        }
    }

    /// If `path` is relative, rebase it onto `self.dir`
    fn dir_rebase(&self, path: &Path) -> PathBuf {
        if path.is_absolute() || self.dir == Path::new(".") {
            path.to_path_buf()
        } else {
            self.dir.join(path)
        }
    }

    /// Path of the working directory
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of the provided binary
    pub fn bin(&self) -> Option<PathBuf> {
        Some(self.dir_rebase(self.bin.as_ref()?))
    }

    /// Path of the provided libc
    pub fn libc(&self) -> Option<PathBuf> {
        Some(self.dir_rebase(self.libc.as_ref()?))
    }

    /// Path of the provided linker
    pub fn ld(&self) -> Option<PathBuf> {
        Some(self.dir_rebase(self.ld.as_ref()?))
    }

    /// Do we have a libc?
    pub fn has_libc(&self) -> bool {
        self.libc.is_some()
    }

    /// Do we have a linker?
    pub fn has_ld(&self) -> bool {
        self.ld.is_some()
    }
}
