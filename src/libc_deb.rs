use std::io::copy;
use std::io::Read;
use std::io::Write;

use lzma::LzmaReader;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;

/// URL for Ubuntu glibc packages. (From one of the few Ubuntu mirrors that uses
/// HTTPS)
pub static PKG_URL: &str = "https://lug.mtu.edu/ubuntu/pool/main/g/glibc";

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

pub fn write_ubuntu_pkg_file<W: Write>(
    deb_url: &str,
    file_name: &str,
    write: &mut W,
) -> Result<()> {
    let deb_bytes = reqwest::get(deb_url).context(DownloadError)?;
    let status = deb_bytes.status();
    if !status.is_success() {
        return Err(Error::DownloadStatusError { status });
    }
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
