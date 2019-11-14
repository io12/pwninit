use crate::opts::Opts;
use crate::set_exec;

use std::path::Path;
use std::path::PathBuf;
use std::string;

use colored::Colorize;
use ex::fs;
use ex::io;
use maplit::hashmap;
use snafu::ResultExt;
use snafu::Snafu;
use strfmt::strfmt;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("solve script template is not valid UTF-8: {}", source))]
    Utf8Error { source: string::FromUtf8Error },

    #[snafu(display("error writing solve script template: {}", source))]
    WriteError { source: io::Error },

    #[snafu(display("error reading solve script template: {}", source))]
    ReadError { source: io::Error },

    #[snafu(display("error filling in solve script template: {}", source))]
    FmtError { source: strfmt::FmtError },

    #[snafu(display("error setting solve script template executable: {}", source))]
    SetExecError { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Make pwntools script that binds the (binary, libc, linker) to `ELF`
/// variables
fn make_bindings(opts: &Opts) -> String {
    let bind_line = |name: &str, opt_path: &Option<PathBuf>| {
        opt_path
            .as_ref()
            .map(|path| format!("{} = ELF(\"{}\")", name, path.display()))
            .unwrap_or_else(|| "".to_string())
    };
    format!(
        "{}\n{}\n{}",
        bind_line(&opts.template_bin_name, &opts.bin),
        bind_line(&opts.template_libc_name, &opts.libc),
        bind_line(&opts.template_ld_name, &opts.ld)
    )
}

/// Make arguments to pwntools `process()` function
fn make_proc_args(opts: &Opts) -> String {
    let args = if opts.ld.is_some() {
        format!(
            "{}.path, {}.path",
            opts.template_ld_name, opts.template_bin_name
        )
    } else {
        format!("{}.path", opts.template_bin_name)
    };

    let env = if opts.libc.is_some() {
        format!(", env={{\"LD_PRELOAD\": {}.path}}", opts.template_libc_name)
    } else {
        "".to_string()
    };

    format!("[{}]{}", args, env)
}

/// Fill in template pwntools solve script with (binary, libc, linker) paths
fn make_stub(opts: &Opts) -> Result<String> {
    let templ = match &opts.template_path {
        Some(path) => {
            let data = fs::read(path).context(ReadError)?;
            String::from_utf8(data).context(Utf8Error)?
        }
        None => include_str!("template.py").to_string(),
    };
    strfmt(
        &templ,
        &hashmap! {
        "bindings".to_string() => make_bindings(opts),
        "proc_args".to_string() => make_proc_args(opts),
        "bin_name".to_string() => opts.template_bin_name.clone(),
        },
    )
    .context(FmtError)
}

/// Write script produced with `make_stub()` to `solve.py` in the
/// specified directory, unless a `solve.py` already exists
pub fn write_stub(opts: &Opts) -> Result<()> {
    let stub = make_stub(opts)?;
    let path = Path::new("solve.py");
    if !path.exists() {
        println!("{}", "writing solve.py stub".cyan().bold());
        fs::write(&path, stub).context(WriteError)?;
        set_exec(&path).context(SetExecError)?;
    }
    Ok(())
}
