use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ex::fs;
use ex::io;

/// Set the file at `path` executable
pub fn set_exec<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    let mode = fs::metadata(path)?.permissions().mode();
    let mode = mode | umask::EXEC;
    let perm = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perm)?;
    Ok(())
}
