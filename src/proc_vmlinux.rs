use crate::opts::Opts;

use std::path::Path;
use std::process::Command;

use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;
use std::fs::File;

use std::io;

#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("extract-vmlinux failed with nonzero exit status"))]
    ExtractVmlinux,

    #[snafu(display("extract-vmlinux failed to start; install it as shown in README.md"))]
    ExtractVmlinuxExec { source: io::Error },
    
    #[snafu(display("vmlinux-to-elf failed to start; install it as shown in README.md"))]
    VmlinuxToElfExec { source: io::Error },

    #[snafu(display("vmlinux-to-elf failed with nonzero exit status"))]
    VmlinuxToElf,
}

pub type Result<T> = std::result::Result<T, Error>;

fn run_extract_vmlinux(bzimage: &Path) -> Result<()> {
    println!(
        "{}",
        format!("running extract-vmlinux on {}", bzimage.to_string_lossy().bold()).green()
    );

    let mut cmd = Command::new("extract-vmlinux");
    let new_vmlinux_file = File::create("./vmlinux").unwrap();
    cmd.arg(bzimage).stdout(std::process::Stdio::from(new_vmlinux_file));
    let status = cmd.status().context(ExtractVmlinuxExecSnafu)?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::ExtractVmlinux)
    }
}

fn run_vmlinux_to_elf(vmlinux: &Path) -> Result<()> {
    println!(
        "{}", 
        format!("running vmlinux-to-elf on {}", vmlinux.to_string_lossy().bold()).green()
    );

    let mut cmd = Command::new("vmlinux-to-elf");
    cmd
        .arg(vmlinux)
        .arg(format!("{}_patched", vmlinux.to_string_lossy()));
    let status = cmd.status().context(VmlinuxToElfExecSnafu)?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::VmlinuxToElf)
    }
}

pub fn extract_vmlinux_from_bzimage(opts: &Opts) -> Result<()> {
    if let Some(bzimage) = &opts.bzimage { 
        run_extract_vmlinux(bzimage)?;
    }

    Ok(())
}

pub fn patch_vmlinux(opts: &Opts) -> Result<()> {
    if let Some(vmlinux) = &opts.vmlinux {
        run_vmlinux_to_elf(vmlinux)?;
    }

    Ok(())
}
