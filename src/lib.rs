//! Utility functions that provide the bulk of ~pwninit~ functionality

mod cpu_arch;
mod elf;
mod fetch_ld;
mod libc_deb;
mod libc_version;
pub mod opts;
mod pwninit;
mod set_exec;
mod solvepy;
mod unstrip_libc;
mod warn;

pub use crate::pwninit::run;
pub use crate::pwninit::Result;

use crate::elf::detect::is_elf;
pub use crate::fetch_ld::fetch_ld;
use crate::libc_version::LibcVersion;
use crate::opts::Opts;
pub use crate::set_exec::set_exec;
pub use crate::unstrip_libc::unstrip_libc;
use crate::warn::Warn;
use crate::warn::WarnResult;

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use colored::Colorize;
use ex::io;
use is_executable::IsExecutable;
use twoway::find_bytes;

/// Detect if `path` is the provided pwn binary
pub fn is_bin(path: &Path) -> elf::detect::Result<bool> {
    Ok(is_elf(path)? && !is_libc(path)? && !is_ld(path)?)
}

/// Does the filename of `path` contain `pattern`?
fn path_contains(path: &Path, pattern: &[u8]) -> bool {
    path.file_name()
        .map(|name| find_bytes(name.as_bytes(), pattern).is_some())
        .unwrap_or(false)
}

/// Detect if `path` is the provided libc
pub fn is_libc(path: &Path) -> elf::detect::Result<bool> {
    Ok(is_elf(path)? && path_contains(path, b"libc"))
}

/// Detect if `path` is the provided linker
pub fn is_ld(path: &Path) -> elf::detect::Result<bool> {
    Ok(is_elf(path)? && path_contains(path, b"ld-"))
}

/// Same as `fetch_ld()`, but doesn't do anything if an existing linker is
/// detected
fn maybe_fetch_ld(opts: &Opts, ver: &LibcVersion) -> fetch_ld::Result {
    match opts.ld {
        Some(_) => Ok(()),
        None => fetch_ld(ver),
    }
}

/// Top-level function for libc-dependent tasks
///   1. Download linker if not found
///   2. Unstrip libc if libc is stripped
fn visit_libc(opts: &Opts, libc: &Path) {
    let ver = match LibcVersion::detect(libc) {
        Ok(ver) => ver,
        Err(err) => {
            err.warn();
            return;
        }
    };
    maybe_fetch_ld(opts, &ver).warn();
    unstrip_libc(libc, &ver).warn();
}

/// Same as `visit_libc()`, but doesn't do anything if no libc is found
pub fn maybe_visit_libc(opts: &Opts) {
    if let Some(libc) = &opts.libc {
        visit_libc(opts, &libc)
    }
}

/// Set the binary executable
pub fn set_bin_exec(opts: &Opts) -> io::Result<()> {
    match &opts.bin {
        Some(bin) => {
            if !bin.is_executable() {
                println!(
                    "{}",
                    format!("setting {} executable", bin.display())
                        .bright_blue()
                        .bold()
                );
                set_exec(&bin)?;
            }
        }
        None => "binary not found".warn(),
    }

    Ok(())
}

/// Set the detected linker executable
pub fn set_ld_exec(opts: &Opts) -> io::Result<()> {
    match &opts.ld {
        Some(ld) if !ld.is_executable() => {
            println!(
                "{}",
                format!("setting {} executable", ld.display())
                    .green()
                    .bold()
            );
            set_exec(&ld)
        }
        _ => Ok(()),
    }
}
