use crate::opts::Opts;

use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use colored::Colorize;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("patchelf failed with nonzero exit status"))]
    Patchelf,

    #[snafu(display("patchelf failed to start; please install patchelf: {}", source))]
    PatchelfExec { source: io::Error },

    #[snafu(display("failed copying file to patch: {}", source))]
    CopyPatched { source: io::Error },

    #[snafu(display("path has no file name: {}", path.display()))]
    FileName { path: PathBuf },

    #[snafu(display("failed symlinking {} -> {}: {}", link.display(), target.display(), source))]
    Symlink {
        link: PathBuf,
        target: PathBuf,
        source: io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

const LIBC_FILE_NAME: &str = "libc.so.6";

/// Run `patchelf` on the binary `bin`.
///
/// If `opts` has a libc, make its directory the RPATH of the binary.
/// If `opts` has a linker, make it the interpreter of the binary.
///
/// Run `patchelf` once per option to avoid broken offsets/symbols (#297)
fn run_patchelf(bin: &Path, opts: &Opts) -> Result<()> {
    println!(
        "{}",
        format!("running patchelf on {}", bin.to_string_lossy().bold()).green()
    );

    if let Some(lib_dir) = opts
        .libc
        .as_ref()
        // Prepend "." in case `libc`'s `parent()` is an empty path.
        .and_then(|libc| Path::new(".").join(libc).parent().map(Path::to_path_buf))
    {
        run_patchelf_option(bin, "--set-rpath", &lib_dir)?;
    };
    if let Some(ld) = &opts.ld {
        run_patchelf_option(bin, "--set-interpreter", ld)?;
    };

    Ok(())
}

/// Run `patchelf` on the binary `bin` using the option `option` with the path `argument`.
fn run_patchelf_option(bin: &Path, option: &str, argument: &PathBuf) -> Result<()> {
    let mut cmd = Command::new("patchelf");
    cmd.arg(bin);
    cmd.arg(option).arg(argument);

    let status = cmd.status().context(PatchelfExecSnafu)?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Patchelf)
    }
}

/// Create a symlink `libc.so.6` pointing to `libc`.
///
/// If `libc` doesn't have the filename `libc.so.6`,
/// make a symlink with file name `libc.so.6` in the same directory as `libc`,
/// and make it point to `libc`.
fn symlink_libc(libc: &Path) -> Result<()> {
    let libc_file_name = libc.file_name().context(FileNameSnafu { path: libc })?;
    if libc_file_name != LIBC_FILE_NAME {
        let link = libc.with_file_name(LIBC_FILE_NAME);
        println!(
            "{}",
            format!(
                "symlinking {} -> {}",
                link.to_string_lossy().bold(),
                libc_file_name.to_string_lossy().bold()
            )
            .green()
        );
        std::os::unix::fs::symlink(libc_file_name, &link).context(SymlinkSnafu {
            link,
            target: libc_file_name,
        })?;
    }
    Ok(())
}

/// Add "_patched" to the end of the binary file name.
///
/// This is like `bin_patched_path()`,
/// but it takes the original paths as input instead of `Opts`.
fn bin_patched_path_from_bin(bin: &Path) -> Result<PathBuf> {
    Ok(bin.with_file_name(
        [
            bin.file_name().context(FileNameSnafu { path: bin })?,
            OsStr::new("_patched"),
        ]
        .iter()
        .map(AsRef::as_ref)
        .collect::<OsString>(),
    ))
}

/// Add "_patched" to the end of the binary file name if the binary got patched.
pub fn bin_patched_path(opts: &Opts) -> Option<PathBuf> {
    match opts.no_patch_bin {
        true => None,
        false => opts
            .bin
            .as_ref()
            .and_then(|bin| bin_patched_path_from_bin(bin).ok()),
    }
}

/// Copy the file `bin` to a file with "_patched" appended to the file name.
/// Return the path to the new file.
fn copy_patched(bin: &Path) -> Result<PathBuf> {
    let bin_patched = bin_patched_path_from_bin(bin)?;
    println!(
        "{}",
        format!(
            "copying {} to {}",
            bin.to_string_lossy().bold(),
            bin_patched.to_string_lossy().bold()
        )
        .green()
    );
    fs::copy(bin, &bin_patched).context(CopyPatchedSnafu)?;

    Ok(bin_patched)
}

/// If `opts` has a binary, patch its RPATH and interpreter.
///
/// Specifically, symlink "libc.so.6" to the libc,
/// copy the binary,
/// and run patchelf on the copied binary.
pub fn patch_bin(opts: &Opts) -> Result<()> {
    if let Some(bin) = &opts.bin {
        if let Some(libc) = &opts.libc {
            symlink_libc(libc)?;
        }

        let bin_patched = copy_patched(bin)?;

        run_patchelf(&bin_patched, opts)?;
    }

    Ok(())
}
