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
use tempfile::TempDir;

#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("libc ELF parse error: {}", source))]
    ElfParse { source: elf::parse::Error },

    #[snafu(display("libc deb error: {}", source))]
    Deb { source: libc_deb::Error },

    #[snafu(display("failed creating temporary directory"))]
    TmpDir { source: std::io::Error },

    #[snafu(display("failed running eu-unstrip, please install elfutils: {}", source))]
    CmdRun { source: std::io::Error },

    #[snafu(display("eu-unstrip exited with failure: {}", status))]
    CmdFail { status: ExitStatus },

    #[snafu(display("failed to open symbol file: {}", source))]
    SymOpen { source: io::Error },

    #[snafu(display("failed to open libc file: {}", source))]
    LibcOpen { source: io::Error },

    #[snafu(display("failed writing symbols to libc file: {}", source))]
    LibcWrite { source: std::io::Error },
}

pub type Result = std::result::Result<(), Error>;

/// Download debug symbols and apply them to a libc
fn do_unstrip_libc(libc: &Path, ver: &LibcVersion) -> Result {
    println!("{}", "unstripping libc".yellow().bold());

    let deb_file_name = format!("libc6-dbg_{}.deb", ver);

    let tmp_dir = TempDir::new().context(TmpDirSnafu)?;

    let sym_path = tmp_dir.path().join("libc-syms");

    let name = format!("libc-{}.so", ver.string_short);

    libc_deb::write_ubuntu_pkg_file(&deb_file_name, &name, &sym_path).context(DebSnafu)?;

    let out = Command::new("eu-unstrip")
        .arg(libc)
        .arg(&sym_path)
        .output()
        .context(CmdRunSnafu)?;
    let _ = stderr().write_all(&out.stderr);
    let _ = stdout().write_all(&out.stdout);
    if !out.status.success() {
        return Err(Error::CmdFail { status: out.status });
    }

    let mut sym_file = File::open(sym_path).context(SymOpenSnafu)?;
    let mut libc_file = File::create(libc).context(LibcOpenSnafu)?;
    copy(&mut sym_file, &mut libc_file).context(LibcWriteSnafu)?;

    Ok(())
}

/// Download debug symbols and apply them to a libc if it doesn't have them
/// already
pub fn unstrip_libc(libc: &Path, ver: &LibcVersion) -> Result {
    if !elf::has_debug_syms(libc).context(ElfParseSnafu)? {
        do_unstrip_libc(libc, ver)?;
    }
    Ok(())
}
