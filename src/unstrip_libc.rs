use crate::elf;
use crate::libc_deb;
use crate::libc_version::LibcVersion;

use std::io::copy;
use std::io::stderr;
use std::io::stdout;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::ExitStatus;

use colored::Colorize;
use ex::fs::File;
use ex::io;
use snafu::ResultExt;
use snafu::Snafu;
use tempdir::TempDir;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("libc ELF parse error: {}", source))]
    ElfParseError { source: elf::parse::Error },

    #[snafu(display("libc deb error: {}", source))]
    DebError { source: libc_deb::Error },

    #[snafu(display("failed creating temporary directory"))]
    TmpDirError { source: std::io::Error },

    #[snafu(display("failed to create symbol file: {}", source))]
    CreateError { source: io::Error },

    #[snafu(display("failed running eu-unstrip, please install elfutils: {}", source))]
    CmdRunError { source: std::io::Error },

    #[snafu(display("eu-unstrip exited with failure: {}", status))]
    CmdFailError { status: ExitStatus },

    #[snafu(display("failed to open symbol file: {}", source))]
    SymOpenError { source: io::Error },

    #[snafu(display("failed to open libc file: {}", source))]
    LibcOpenError { source: io::Error },

    #[snafu(display("failed writing symbols to libc file: {}", source))]
    LibcWriteError { source: std::io::Error },
}

pub type Result = std::result::Result<(), Error>;

/// Download debug symbols and apply them to a libc
fn do_unstrip_libc(libc: &Path, ver: &LibcVersion) -> Result {
    println!("{}", "unstripping libc".yellow().bold());

    let url = format!("{}/libc6-dbg_{}.deb", libc_deb::PKG_URL, ver);

    let tmp_dir_name = "pwninit-unstrip";
    let tmp_dir = TempDir::new(tmp_dir_name).context(TmpDirError)?;

    let sym_path = tmp_dir.path().join("libc-syms");
    let mut sym_file = File::create(&sym_path).context(CreateError)?;

    let name = format!("libc-{}.so", ver.string_short);

    libc_deb::write_ubuntu_pkg_file(&url, &name, &mut sym_file).context(DebError)?;

    let out = Command::new("eu-unstrip")
        .arg(libc)
        .arg(&sym_path)
        .output()
        .context(CmdRunError)?;
    let _ = stderr().write_all(&out.stderr);
    let _ = stdout().write_all(&out.stdout);
    if !out.status.success() {
        return Err(Error::CmdFailError { status: out.status });
    }

    let mut sym_file = File::open(sym_path).context(SymOpenError)?;
    let mut libc_file = File::create(libc).context(LibcOpenError)?;
    copy(&mut sym_file, &mut libc_file).context(LibcWriteError)?;

    Ok(())
}

/// Download debug symbols and apply them to a libc if it doesn't have them
/// already
pub fn unstrip_libc(libc: &Path, ver: &LibcVersion) -> Result {
    if !elf::has_debug_syms(libc).context(ElfParseError)? {
        do_unstrip_libc(libc, ver)?;
    }
    Ok(())
}
