use crate::maybe_visit_libc;
use crate::opts;
use crate::patch_bin;
use crate::set_bin_exec;
use crate::set_ld_exec;
use crate::solvepy;
use crate::Opts;

use ex::io;
use snafu::ResultExt;
use snafu::Snafu;

/// Top-level `pwninit` error
#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed setting binary executable: {}", source))]
    SetBinExec { source: io::Error },

    #[snafu(display("failed locating provided files (binary, libc, linker): {}", source))]
    Find { source: opts::Error },

    #[snafu(display("failed setting linker executable: {}", source))]
    SetLdExec { source: io::Error },

    #[snafu(display("failed patching binary: {}", source))]
    PatchBin { source: patch_bin::Error },

    #[snafu(display("failed making template solve script: {}", source))]
    Solvepy { source: solvepy::Error },
}

pub type Result = std::result::Result<(), Error>;

/// Run `pwninit` with specified options
pub fn run(opts: Opts) -> Result {
    // Detect unspecified files
    let opts = opts.find_if_unspec().context(FindSnafu)?;

    // Print detected files
    opts.print();
    println!();

    set_bin_exec(&opts).context(SetBinExecSnafu)?;
    maybe_visit_libc(&opts);

    // Redo detection in case the ld was downloaded
    let opts = opts.find_if_unspec().context(FindSnafu)?;

    set_ld_exec(&opts).context(SetLdExecSnafu)?;

    if !opts.no_patch_bin {
        patch_bin::patch_bin(&opts).context(PatchBinSnafu)?;
    }

    if !opts.no_template {
        solvepy::write_stub(&opts).context(SolvepySnafu)?;
    }

    Ok(())
}
