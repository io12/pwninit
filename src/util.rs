//! Utility functions that provide the bulk of ~pwninit~ functionality

use colored::Colorize;
use goblin::elf::Elf;
use is_executable::IsExecutable;
use lzma::reader::LzmaReader;
use tempdir::TempDir;
use twoway::find_bytes;

use crate::libc_version::LibcVersion;
use crate::opts::Opts;
use crate::Result;

use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// URL for Ubuntu glibc packages. (From one of the few Ubuntu mirrors that uses
/// HTTPS)
static LIBC_URL: &str = "https://lug.mtu.edu/ubuntu/pool/main/g/glibc";

/// Helper for `is_elf` that uses `Result` early returns for conciseness
fn is_elf_result(path: &Path) -> Result<bool> {
    Ok(File::open(path)?
        .bytes()
        .take(4)
        .collect::<io::Result<Vec<u8>>>()?
        == b"\x7fELF")
}

/// Is the binary at `path` an ELF?
fn is_elf(path: &Path) -> bool {
    is_elf_result(path).unwrap_or(false)
}

/// Detect if `path` is the provided pwn binary
pub fn is_bin(path: &Path) -> bool {
    is_elf(path) && !is_libc(path) && !is_ld(path)
}

/// Does the filename of `path` contain `pattern`?
fn path_contains(path: &Path, pattern: &[u8]) -> bool {
    path.file_name()
        .map(|name| find_bytes(name.as_bytes(), pattern).is_some())
        .unwrap_or(false)
}

/// Detect if `path` is the provided libc
pub fn is_libc(path: &Path) -> bool {
    is_elf(path) && path_contains(path, b"libc")
}

/// Detect if `path` is the provided linker
pub fn is_ld(path: &Path) -> bool {
    is_elf(path) && path_contains(path, b"ld-")
}

/// Helper function for `fetch_ld()` that decides whether the tar file `entry`
/// matches `file_name`
fn tar_entry_matches<R: Read>(entry: &io::Result<tar::Entry<R>>, file_name: &str) -> bool {
    match entry {
        Ok(entry) => match entry.path() {
            Ok(path) => path.file_name() == Some(file_name.as_ref()),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// Download linker compatible with libc version `ver` and save to directory
/// `dir`
fn fetch_ld(dir: &Path, ver: &LibcVersion) -> Result<()> {
    println!("{}", "fetching linker".green().bold());

    let error = || io::Error::new(io::ErrorKind::NotFound, "failed to fetch linker");
    let url = format!("{}/libc6_{}.deb", LIBC_URL, ver);
    let deb_bytes = reqwest::get(&url)?;
    let mut deb = ar::Archive::new(deb_bytes);

    while let Some(Ok(entry)) = deb.next_entry() {
        if entry.header().identifier() == b"data.tar.xz" {
            let data_tar_bytes = LzmaReader::new_decompressor(entry)?;
            let mut data_tar = tar::Archive::new(data_tar_bytes);
            let ld_name = format!("ld-{}.so", ver.string_short);
            let mut ld_entry = data_tar
                .entries()?
                .find(|entry| tar_entry_matches(entry, &ld_name))
                .ok_or_else(error)??;
            let path = dir.join(ld_name);
            io::copy(&mut ld_entry, &mut File::create(path)?)?;
            return Ok(());
        }
    }
    Err(error().into())
}

/// Same as `fetch_ld()`, but doesn't do anything if an existing linker is
/// detected
fn maybe_fetch_ld(opts: &Opts, ver: &LibcVersion) -> Result<()> {
    match opts.ld() {
        Some(_) => Ok(()),
        None => fetch_ld(opts.dir(), ver),
    }
}

/// Download debug symbols and apply them to a libc
fn unstrip_libc(libc: &Path, ver: &LibcVersion) -> Result<()> {
    println!("{}", "unstripping libc".yellow().bold());

    let error = || io::Error::new(io::ErrorKind::NotFound, "failed to unstrip libc");
    let url = format!("{}/libc6-dbg_{}.deb", LIBC_URL, ver);
    let deb_bytes = reqwest::get(&url)?;
    let mut deb = ar::Archive::new(deb_bytes);

    while let Some(Ok(entry)) = deb.next_entry() {
        if entry.header().identifier() == b"data.tar.xz" {
            let data_tar_bytes = LzmaReader::new_decompressor(entry)?;
            let mut data_tar = tar::Archive::new(data_tar_bytes);
            let name = format!("libc-{}.so", ver.string_short);
            let mut entry = data_tar
                .entries()?
                .find(|entry| tar_entry_matches(entry, &name))
                .ok_or_else(error)??;
            let tmp_dir = TempDir::new("pwninit-unstrip")?;
            let sym_path = tmp_dir.path().join("libc-syms");
            io::copy(&mut entry, &mut File::create(&sym_path)?)?;
            let out = Command::new("eu-unstrip")
                .arg(libc)
                .arg(&sym_path)
                .output()?;
            io::stderr().write_all(&out.stderr)?;
            io::stdout().write_all(&out.stdout)?;
            if !out.status.success() {
                return Err(error().into());
            }
            io::copy(&mut File::open(sym_path)?, &mut File::create(libc)?)?;
            return Ok(());
        }
    }
    Err(error().into())
}

/// Same as `unstrip_libc()` but it doesn't do anything if the libc already has
/// debug symbols
fn maybe_unstrip_libc(libc: &Path, ver: &LibcVersion) -> Result<()> {
    if !has_debug_syms(libc)? {
        unstrip_libc(libc, ver)?;
    }
    Ok(())
}

/// Top-level function for libc-dependent tasks
///   1. Download linker if not found
///   2. Unstrip libc if libc is stripped
fn visit_libc(opts: &Opts, libc: &Path) -> Result<()> {
    let ver = LibcVersion::detect(libc)?;
    maybe_fetch_ld(opts, &ver)?;
    maybe_unstrip_libc(libc, &ver)?;
    Ok(())
}

/// Same as `visit_libc()`, but doesn't do anything if no libc is found
pub fn maybe_visit_libc(opts: &Opts) -> Result<()> {
    match opts.libc() {
        Some(libc) => visit_libc(opts, &libc),
        None => Ok(()),
    }
}

/// Set the file at `path` executable
pub fn set_exec<P: AsRef<Path>>(path: P) -> Result<()> {
    let mode = path.as_ref().metadata()?.permissions().mode();
    let mode = mode | umask::EXEC;
    let perm = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perm)?;
    Ok(())
}

/// Set the detected binary executable
pub fn set_bin_exec(opts: &Opts) -> Result<()> {
    let bin = opts
        .bin()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "binary not found"))?;

    if !bin.is_executable() {
        println!(
            "{}",
            format!("setting {} executable", bin.display())
                .bright_blue()
                .bold()
        );
        set_exec(&bin)?;
    }

    Ok(())
}

/// Set the detected linker executable
pub fn set_ld_exec(opts: &Opts) -> Result<()> {
    match &opts.ld() {
        Some(ld) if !ld.is_executable() => {
            println!(
                "{}",
                format!("setting {} executable", ld.display())
                    .green()
                    .bold()
            );
            set_exec(&ld)
        }
        _ => Ok(()),
    }
}

/// Does the ELF at `path` have debug symbols?
///
/// Errors:
///   - Failed to read file
///   - Failed to parse file as ELF
pub fn has_debug_syms(path: &Path) -> Result<bool> {
    let bytes = fs::read(path)?;
    let elf = Elf::parse(&bytes)?;
    Ok(elf.section_headers.iter().any(|hdr| {
        elf.shdr_strtab
            .get(hdr.sh_name)
            .map(|s| s.map(|s| s == ".debug_info").unwrap_or(false))
            .unwrap_or(false)
    }))
}

/// Make pwntools script that binds the (binary, libc, linker) to `ELF`
/// variables
fn make_bindings(opts: &Opts) -> String {
    let bind_line = |name: &str, opt_path: Option<PathBuf>| {
        opt_path
            .map(|path| format!("{} = ELF(\"{}\")\n", name, path.display()))
            .unwrap_or_else(|| "".to_string())
    };
    format!(
        "{}{}{}",
        bind_line("elf", opts.bin()),
        bind_line("libc", opts.libc()),
        bind_line("ld", opts.ld())
    )
}

/// Make arguments to pwntools `process()` function
fn make_proc_args(opts: &Opts) -> String {
    format!(
        "[{}]{}",
        if opts.has_ld() {
            "ld.path, elf.path"
        } else {
            "elf.path"
        },
        if opts.has_libc() {
            ", env={\"LD_PRELOAD\": libc.path}"
        } else {
            ""
        }
    )
}

/// Fill in template pwntools solve script with (binary, libc, linker) paths
fn make_solvepy_stub(opts: &Opts) -> String {
    let templ = include_str!("solve.py");
    let bindings = make_bindings(opts);
    let proc_args = make_proc_args(opts);
    templ
        .replace("BINDINGS", &bindings)
        .replace("PROC_ARGS", &proc_args)
}

/// Write script produced with `make_solvepy_stub()` to `solve.py` in the
/// specified directory, unless a `solve.py` already exists
pub fn write_solvepy_stub(opts: &Opts) -> Result<()> {
    let stub = make_solvepy_stub(opts);
    let path = opts.dir().join("solve.py");
    if !path.exists() {
        println!("{}", "writing solve.py stub".magenta().bold());
        fs::write(&path, stub)?;
        set_exec(&path)?;
    }
    Ok(())
}
