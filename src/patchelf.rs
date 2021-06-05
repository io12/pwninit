use crate::opts::Opts;
use std::fs;
use std::io::{self, Error, ErrorKind, Write};
use std::process::Command;

pub fn patch_rpath(opts: &Opts) -> io::Result<()> {
    let bin = opts.bin.as_ref().unwrap();
    let abs_path = fs::canonicalize(bin)?;
    let binary_path = abs_path.as_os_str();
    let current_path = abs_path.parent().unwrap().as_os_str();
    let output = Command::new("patchelf")
        .arg("--set-rpath")
        .arg(current_path)
        .arg(binary_path)
        .output()
        .expect("patch rpath failed");
    let status = output.status;
    io::stdout().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();
    if status.success() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, "patchelf rpath error"))
    }
}

pub fn patch_interpreter(opts: &Opts) -> io::Result<()> {
    let abs_ld_path = fs::canonicalize(opts.ld.as_ref().unwrap())?;
    let ld_path = abs_ld_path.as_os_str();
    let bin = opts.bin.as_ref().unwrap();
    let abs_path = fs::canonicalize(bin)?;
    let binary_path = abs_path.as_os_str();
    let output = Command::new("patchelf")
        .arg("--set-interpreter")
        .arg(ld_path)
        .arg(binary_path)
        .output()
        .expect("patch interpreter failed");
    let status = output.status;
    io::stdout().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();
    if status.success() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, "patchelf interpreter error"))
    }
}
