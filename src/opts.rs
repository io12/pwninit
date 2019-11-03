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
        let dir = fs::read_dir(".")?;
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
            bin: self.bin.or_else(|| f(util::is_bin)),
            libc: self.libc.or_else(|| f(util::is_libc)),
            ld: self.ld.or_else(|| f(util::is_ld)),
        }
    }
}
