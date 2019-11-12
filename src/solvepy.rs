use crate::opts::Opts;
use crate::set_exec;

use std::path::Path;
use std::path::PathBuf;

use colored::Colorize;
use ex::fs;
use ex::io;

/// Make pwntools script that binds the (binary, libc, linker) to `ELF`
/// variables
fn make_bindings(opts: &Opts) -> String {
    let bind_line = |name: &str, opt_path: &Option<PathBuf>| {
        opt_path
            .as_ref()
            .map(|path| format!("{} = ELF(\"{}\")\n", name, path.display()))
            .unwrap_or_else(|| "".to_string())
    };
    format!(
        "{}{}{}",
        bind_line("exe", &opts.bin),
        bind_line("libc", &opts.libc),
        bind_line("ld", &opts.ld)
    )
}

/// Make arguments to pwntools `process()` function
fn make_proc_args(opts: &Opts) -> String {
    format!(
        "[{}]{}",
        if opts.ld.is_some() {
            "ld.path, exe.path"
        } else {
            "exe.path"
        },
        if opts.libc.is_some() {
            ", env={\"LD_PRELOAD\": libc.path}"
        } else {
            ""
        }
    )
}

/// Fill in template pwntools solve script with (binary, libc, linker) paths
fn make_stub(opts: &Opts) -> String {
    let templ = include_str!("template.py");
    let bindings = make_bindings(opts);
    let proc_args = make_proc_args(opts);
    templ
        .replace("BINDINGS", &bindings)
        .replace("PROC_ARGS", &proc_args)
}

/// Write script produced with `make_solvepy_stub()` to `solve.py` in the
/// specified directory, unless a `solve.py` already exists
pub fn write_stub(opts: &Opts) -> io::Result<()> {
    let stub = make_stub(opts);
    let path = Path::new("solve.py");
    if !path.exists() {
        println!("{}", "writing solve.py stub".cyan().bold());
        fs::write(&path, stub)?;
        set_exec(&path)?;
    }
    Ok(())
}
