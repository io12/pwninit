use crate::libc_deb;
use crate::libc_version::LibcVersion;

use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("libc deb error: {}", source))]
    DebError { source: libc_deb::Error },

    #[snafu(display("failed writing to linker file: {}", source))]
    WriteError { source: std::io::Error },
}

pub type Result = std::result::Result<(), Error>;

/// Download linker compatible with libc version `ver` and save to directory
/// `dir`
pub fn fetch_ld(ver: &LibcVersion) -> Result {
    println!("{}", "fetching linker".green().bold());

    let deb_file_name = format!("libc6_{}.deb", ver);
    let ld_name = format!("ld-{}.so", ver.string_short);
    libc_deb::write_ubuntu_pkg_file(&deb_file_name, &ld_name, &ld_name).context(DebError)?;
    Ok(())
}
