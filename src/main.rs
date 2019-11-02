mod cpu_arch;
mod libc_version;
mod opts;
mod util;

use crate::opts::Opts;

use structopt::StructOpt;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn try_main() -> Result<()> {
    let opts = Opts::from_args();
    let opts = opts.find_if_unspec()?;

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

fn main() {
    if let Err(err) = try_main() {
        eprintln!("pwninit: error: {}", err);
        std::process::exit(1);
    }
}
