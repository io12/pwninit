use crate::maybe_visit_libc;
use crate::opts;
use crate::set_bin_exec;
use crate::set_ld_exec;
use crate::solvepy;
use crate::Opts;

use ex::io;
use snafu::ResultExt;
use snafu::Snafu;

/// Top-level `pwninit` error
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed setting binary executable: {}", source))]
    SetBinExecError { source: io::Error },

    #[snafu(display("failed locating provided files (binary, libc, linker): {}", source))]
    FindError { source: opts::Error },

    #[snafu(display("failed setting linker executable: {}", source))]
    SetLdExecError { source: io::Error },

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
    solvepy::write_stub(&opts).context(SolvepyError)?;

    Ok(())
}
