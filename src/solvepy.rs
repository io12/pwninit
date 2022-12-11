use crate::opts::Opts;
use crate::patch_bin;
use crate::set_exec;

use std::path::Path;
use std::string;

use colored::Colorize;
use ex::fs;
use ex::io;
use maplit::hashmap;
use snafu::ResultExt;
use snafu::Snafu;
use strfmt::strfmt;

#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("solve script template is not valid UTF-8: {}", source))]
    Utf8 { source: string::FromUtf8Error },

    #[snafu(display("error writing solve script template: {}", source))]
    Write { source: io::Error },

    #[snafu(display("error reading solve script template: {}", source))]
    Read { source: io::Error },

    #[snafu(display("error filling in solve script template: {}", source))]
    Fmt { source: strfmt::FmtError },

    #[snafu(display("error setting solve script template executable: {}", source))]
    SetExec { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Make pwntools script that binds the (binary, libc, linker) to `ELF`
/// variables
fn make_bindings(opts: &Opts) -> String {
    // Helper to make one binding line
    fn bind_line<P: AsRef<Path>>(name: &str, opt_path: Option<P>) -> Option<String> {
        opt_path
            .as_ref()
            .map(|path| format!("{} = ELF(\"{}\")", name, path.as_ref().display(),))
    }

    // Create bindings and join them with newlines
    [
        bind_line(
            &opts.template_bin_name,
            patch_bin::bin_patched_path(opts)
                .as_ref()
                .or(opts.bin.as_ref()),
        ),
        bind_line(&opts.template_libc_name, opts.libc.as_ref()),
        bind_line(&opts.template_ld_name, opts.ld.as_ref()),
    ]
    .iter()
    .filter_map(|x| x.as_ref())
    .cloned()
    .collect::<Vec<String>>()
    .join("\n")
}

/// Make arguments to pwntools `process()` function
fn make_proc_args(opts: &Opts) -> String {
    format!("[{}.path]", opts.template_bin_name)
}

/// Fill in template pwntools solve script with (binary, libc, linker) paths
fn make_stub(opts: &Opts) -> Result<String> {
    let templ = match &opts.template_path {
        Some(path) => {
            let data = fs::read(path).context(ReadSnafu)?;
            String::from_utf8(data).context(Utf8Snafu)?
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
    .context(FmtSnafu)
}

/// Write script produced with `make_stub()` to `solve.py` in the
/// specified directory, unless a `solve.py` already exists
pub fn write_stub(opts: &Opts) -> Result<()> {
    let stub = make_stub(opts)?;
    let path = Path::new("solve.py");
    if !path.exists() {
        println!("{}", "writing solve.py stub".cyan().bold());
        fs::write(&path, stub).context(WriteSnafu)?;
        set_exec(&path).context(SetExecSnafu)?;
    }
    Ok(())
}
