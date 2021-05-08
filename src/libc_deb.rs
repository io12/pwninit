use std::ffi::OsStr;
use std::io::copy;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use ex::fs::File;
use ex::io;
use flate2::read::GzDecoder;
use lzma::LzmaReader;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Snafu;

/// URL for Ubuntu glibc packages
pub static PKG_URL: &str = "https://launchpad.net/ubuntu/+archive/primary/+files/";

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

    #[snafu(display("failed decompressing data.tar: {}", source))]
    DataUnzipError { source: lzma::LzmaError },

    #[snafu(display("failed getting data.tar entries: {}", source))]
    DataEntriesError { source: std::io::Error },

    #[snafu(display("failed to find file in data.tar"))]
    FileNotFoundError,

    #[snafu(display("failed reading file entry in data.tar: {}", source))]
    ReadError { source: std::io::Error },

    #[snafu(display("failed to write file from deb: {}", source))]
    WriteError { source: std::io::Error },

    #[snafu(display("failed to create file: {}", source))]
    CreateError { source: io::Error },

    #[snafu(display("failed to find data.tar in package"))]
    DataNotFoundError,

    #[snafu(display(
        "data.tar in package has unknown extension: {}",
        String::from_utf8_lossy(ext)
    ))]
    DataExtError { ext: Vec<u8> },
}

/// Try to download a file from a URL
fn request_url(url: &str) -> Result<reqwest::blocking::Response> {
    let resp = reqwest::blocking::get(url).context(DownloadError)?;
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        Err(Error::DownloadStatusError { status })
    }
}

/// Try to get a glibc deb package with a given filename, checking both current
/// and archive Ubuntu mirrors
fn request_ubuntu_pkg(deb_file_name: &str) -> Result<reqwest::blocking::Response> {
    let url = format!("{}/{}", PKG_URL, deb_file_name);
    request_url(&url)
}

/// Download the glibc deb package with a given name, find a file inside it, and
/// extract the file.
pub fn write_ubuntu_pkg_file<P: AsRef<Path>>(
    deb_file_name: &str,
    file_name: &str,
    out_path: P,
) -> Result<()> {
    let out_path = out_path.as_ref();

    let deb_bytes = request_ubuntu_pkg(deb_file_name)?;
    let mut deb = ar::Archive::new(deb_bytes);

    // Try to find data.tar in package
    while let Some(Ok(entry)) = deb.next_entry() {
        let path = entry.header().identifier();
        let path = Path::new(OsStr::from_bytes(path));

        let stem = path.file_stem().map(OsStr::as_bytes);
        if stem != Some(b"data.tar") {
            continue;
        }

        // Detect extension and decompress
        let ext = path
            .extension()
            .map(OsStr::as_bytes)
            .context(DataNotFoundError)?;
        match ext {
            b"gz" => {
                let data = GzDecoder::new(entry);
                write_ubuntu_data_tar_file(data, file_name, out_path)
            }
            b"xz" => {
                let data = LzmaReader::new_decompressor(entry).context(DataUnzipError)?;
                write_ubuntu_data_tar_file(data, file_name, out_path)
            }
            ext => None.context(DataExtError { ext }),
        }?;

        return Ok(());
    }

    Err(Error::DataNotFoundError)
}

/// Given the bytes of a data.tar in a glibc deb package, find a file inside it,
/// and extract the file.
fn write_ubuntu_data_tar_file<R: Read>(
    data_tar_bytes: R,
    file_name: &str,
    out_path: &Path,
) -> Result<()> {
    let mut data_tar = tar::Archive::new(data_tar_bytes);
    let mut entry = data_tar
        .entries()
        .context(DataEntriesError)?
        .find(|entry| tar_entry_matches(entry, file_name))
        .context(FileNotFoundError)?
        .context(ReadError)?;
    let mut out_file = File::create(out_path).context(CreateError)?;
    copy(&mut entry, &mut out_file).context(WriteError)?;
    Ok(())
}
