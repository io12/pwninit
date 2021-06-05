use crate::maybe_visit_libc;
use crate::opts;
use crate::patchelf;
use crate::set_bin_exec;
use crate::set_ld_exec;
use crate::solvepy;
use crate::Opts;
use colored::Colorize;

use ex::io;
use snafu::ResultExt;
use snafu::Snafu;
use std::fs;
use std::path::Path;

/// Top-level `pwninit` error
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed setting binary executable: {}", source))]
    SetBinExecError { source: io::Error },

    #[snafu(display("failed locating provided files (binary, libc, linker): {}", source))]
    FindError { source: opts::Error },

    #[snafu(display("failed setting linker executable: {}", source))]
    SetLdExecError { source: io::Error },

    #[snafu(display("failed patching elf: {}", source))]
    PatchELFError { source: std::io::Error },

    #[snafu(display("failed making template solve script: {}", source))]
    SolvepyError { source: solvepy::Error },
}

pub type Result = std::result::Result<(), Error>;

/// Run `pwninit` with specified options
pub fn run(opts: Opts) -> Result {
    // Detect unspecified files
    let opts = opts.find_if_unspec().context(FindError)?;

    // Print detected files
    opts.print();
    println!();

    set_bin_exec(&opts).context(SetBinExecError)?;
    maybe_visit_libc(&opts);

    // Redo detection in case the ld was downloaded
    let opts = opts.find_if_unspec().context(FindError)?;

    set_ld_exec(&opts).context(SetLdExecError)?;

    if opts.patchelf {
        let path = opts
            .clone()
            .bin
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap();
        let orig_path = Path::new(&path);
        let backup_str = format!("{}_orig", path);
        let backup_path = Path::new(&backup_str);
        std::os::unix::fs::symlink(opts.clone().libc.unwrap(), "libc.so.6")
            .context(PatchELFError)?;
        fs::copy(orig_path, backup_path).context(PatchELFError)?;
        println!(
            "{}",
            format!(
                "copy from {} to {}",
                orig_path.display(),
                backup_path.display()
            )
            .green()
            .bold()
        );
        println!(
            "{}",
            format!("running patchelf on {}", backup_path.display())
                .green()
                .bold()
        );
        patchelf::patch_rpath(&opts).context(PatchELFError)?;
        patchelf::patch_interpreter(&opts).context(PatchELFError)?;
    }

    if !opts.no_template {
        solvepy::write_stub(&opts).context(SolvepyError)?;
    }
    Ok(())
}
