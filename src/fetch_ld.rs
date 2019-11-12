use crate::libc_deb;
use crate::libc_version::LibcVersion;

use colored::Colorize;
use ex::fs::File;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("libc deb error: {}", source))]
    DebError { source: libc_deb::Error },

    #[snafu(display("failed to create linker file: {}", source))]
    CreateError { source: io::Error },

    #[snafu(display("failed writing to linker file: {}", source))]
    WriteError { source: std::io::Error },
}

pub type Result = std::result::Result<(), Error>;

/// Download linker compatible with libc version `ver` and save to directory
/// `dir`
pub fn fetch_ld(ver: &LibcVersion) -> Result {
    println!("{}", "fetching linker".green().bold());

    let url = format!("{}/libc6_{}.deb", libc_deb::PKG_URL, ver);
    let ld_name = format!("ld-{}.so", ver.string_short);
    let mut ld_file = File::create(&ld_name).context(CreateError)?;
    libc_deb::write_ubuntu_pkg_file(&url, &ld_name, &mut ld_file).context(DebError)?;
    Ok(())
}
