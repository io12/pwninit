use crate::warn::Warn;

use std::io::copy;
use std::io::Read;
use std::io::Write;

use colored::Colorize;
use lzma::LzmaReader;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;

/// URL for new Ubuntu glibc packages. This is one of the few Ubuntu mirrors
/// that uses HTTPS.
pub static PKG_URL_NEW: &str = "https://mirrors.edge.kernel.org/ubuntu/pool/main/g/glibc";

/// URL for old Ubuntu glibc packages. Note that "old package" doesn't
/// necessarily correspond to "old glibc version." This is one of the few Ubuntu
/// archive mirrors that uses HTTPS.
pub static PKG_URL_OLD: &str =
    "https://mirror.math.princeton.edu/pub/ubuntu-archive/ubuntu/pool/main/g/glibc";

pub type Result<T> = std::result::Result<T, Error>;

/// Helper function that decides whether the tar file `entry` matches
/// `file_name`
fn tar_entry_matches<R: Read>(entry: &std::io::Result<tar::Entry<R>>, file_name: &str) -> bool {
    match entry {
        Ok(entry) => match entry.path() {
            Ok(path) => path.file_name() == Some(file_name.as_ref()),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to download package from Ubuntu mirror: {}", source))]
    DownloadError { source: reqwest::Error },

    #[snafu(display(
        "failed to download package from Ubuntu mirror: status code: {}",
        status
    ))]
    DownloadStatusError { status: reqwest::StatusCode },

    #[snafu(display("failed decompressing data.tar.xz: {}", source))]
    DataUnzipError { source: lzma::LzmaError },

    #[snafu(display("failed getting data.tar.xz entries: {}", source))]
    DataEntriesError { source: std::io::Error },

    #[snafu(display("failed to find file in data.tar.xz"))]
    FileNotFoundError,

    #[snafu(display("failed reading file entry in data.tar.xz: {}", source))]
    ReadError { source: std::io::Error },

    #[snafu(display("failed to write file from deb: {}", source))]
    WriteError { source: std::io::Error },

    #[snafu(display("failed to find data.tar.xz in package"))]
    DataNotFoundError,
}

/// Try to download a file from a URL
fn request_url(url: &str) -> Result<reqwest::Response> {
    let resp = reqwest::get(url).context(DownloadError)?;
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        Err(Error::DownloadStatusError { status })
    }
}

/// Try to get a glibc deb package with a given filename, checking both current
/// and archive Ubuntu mirrors
fn request_ubuntu_pkg(deb_file_name: &str) -> Result<reqwest::Response> {
    let url_new = format!("{}/{}", PKG_URL_NEW, deb_file_name);
    let url_old = format!("{}/{}", PKG_URL_OLD, deb_file_name);

    match request_url(&url_new) {
        Ok(resp) => return Ok(resp),
        Err(err) => {
            err.warn("failed fetching Ubuntu glibc deb package");
            println!("{}", "trying archive mirror".bright_blue().bold());
        }
    };

    request_url(&url_old)
}

/// Download the glibc deb package with a given name, find a file inside it, and
/// write the file to a specified sink.
pub fn write_ubuntu_pkg_file<W: Write>(
    deb_file_name: &str,
    file_name: &str,
    write: &mut W,
) -> Result<()> {
    let deb_bytes = request_ubuntu_pkg(deb_file_name)?;
    let mut deb = ar::Archive::new(deb_bytes);

    while let Some(Ok(entry)) = deb.next_entry() {
        if entry.header().identifier() == b"data.tar.xz" {
            let data_tar_bytes = LzmaReader::new_decompressor(entry).context(DataUnzipError)?;
            let mut data_tar = tar::Archive::new(data_tar_bytes);
            let mut entry = data_tar
                .entries()
                .context(DataEntriesError)?
                .find(|entry| tar_entry_matches(entry, file_name))
                .context(FileNotFoundError)?
                .context(ReadError)?;
            copy(&mut entry, write).context(WriteError)?;
            return Ok(());
        }
    }

    Err(Error::DataNotFoundError)
}
