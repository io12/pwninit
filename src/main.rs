//! Top-level main code for `pwninit`

mod cpu_arch;
mod libc_version;
mod opts;
mod util;

use crate::opts::Opts;

use colored::Colorize;
use structopt::StructOpt;

/// ~Result~ wrapper that specialized ~Result~ types can convert to
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Parse command line options and set up specified directory for pwning
fn try_main() -> Result<()> {
    // Parse arguments and guess unspecified values
    let opts = Opts::from_args();
    let opts = opts.find_if_unspec()?;

    // Print detected files
    opts.print();
    println!();

    util::set_bin_exec(&opts)?;
    util::maybe_visit_libc(&opts)?;

    // Redo detection in case the ld was downloaded
    let opts = opts.find_if_unspec()?;

    util::set_ld_exec(&opts)?;
    util::write_solvepy_stub(&opts)?;

    Ok(())
}

/// Top-level error catcher
fn main() {
    if let Err(err) = try_main() {
        eprintln!("{}", format!("error: {}", err).red().bold());
        std::process::exit(1);
    }
}
