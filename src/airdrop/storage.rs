//! Disk-backed bounded transfer decoding and atomic publication.
use anyhow::{bail, ensure, Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
pub const MAX_TRANSFER: u64 = 32 * 1024 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 65536;
fn bounded_copy(mut source: impl Read, out: &mut impl Write, limit: u64) -> Result<u64> {
    let n = std::io::copy(&mut source.by_ref().take(limit + 1), out)?;
    ensure!(n <= limit, "transfer exceeds 32 GiB limit");
    Ok(n)
}
fn number(b: &[u8], radix: u32) -> Result<u64> {
    Ok(u64::from_str_radix(std::str::from_utf8(b)?, radix)?)
}
fn relative(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.starts_with('/') && !name.contains('\\') && name.len() <= 4096,
        "unsafe archive path"
    );
    let mut result = PathBuf::new();
    for part in name.split('/') {
        if part == "." || part.is_empty() {
            continue;
        }
        ensure!(
            part != ".."
                && part.len() <= 255
                && !part.chars().any(|c| c.is_control()
                    || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')),
            "unsafe archive component"
        );
        result.push(part);
    }
    ensure!(!result.as_os_str().is_empty(), "empty archive path");
    Ok(result)
}
fn decoded(
    mut file: File,
    ty: &str,
    token: super::cancel::Token,
) -> Result<tempfile::NamedTempFile> {
    let mut output = tempfile::NamedTempFile::new()?;
    let mut prefix = [0; 2];
    let count = file.read(&mut prefix)?;
    file.rewind()?;
    let mut file = super::cancel::Reader { inner: file, token };
    if count == 2 && prefix == [31, 139] {
        bounded_copy(
            flate2::read::GzDecoder::new(file),
            output.as_file_mut(),
            MAX_TRANSFER,
        )?;
    } else if ty == "application/x-dvzip" {
        let mut written = 0;
        loop {
            let mut header = [0; 4];
            let n = file.read(&mut header[..1])?;
            if n == 0 {
                break;
            }
            file.read_exact(&mut header[1..])?;
            let header = u32::from_be_bytes(header);
            let size = (header & 0x7fffffff) as u64;
            ensure!(size > 0, "empty DVZip block");
            let mut block = (&mut file).take(size);
            let n = if header & 0x80000000 != 0 {
                bounded_copy(&mut block, output.as_file_mut(), MAX_TRANSFER - written)?
            } else {
                bounded_copy(
                    flate2::read::ZlibDecoder::new(&mut block),
                    output.as_file_mut(),
                    MAX_TRANSFER - written,
                )?
            };
            // Consume the entire bounded block, including any decoder buffering.
            std::io::copy(&mut block, &mut std::io::sink())?;
            ensure!(block.limit() == 0, "truncated DVZip block");
            written += n;
        }
    } else {
        ensure!(ty == "application/x-cpio", "unsupported archive media type");
        bounded_copy(file, output.as_file_mut(), MAX_TRANSFER)?;
    }
    output.as_file_mut().rewind()?;
    Ok(output)
}
pub struct Saved {
    pub directory: PathBuf,
    pub files: usize,
    pub bytes: u64,
    pub clipboard: Vec<super::archive::Entry>,
}
#[cfg(test)]
pub fn receive(file: File, ty: &str, dest: &Path) -> Result<Saved> {
    receive_cancel(file, ty, dest, super::cancel::Token::default())
}
pub fn receive_cancel(
    file: File,
    ty: &str,
    dest: &Path,
    token: super::cancel::Token,
) -> Result<Saved> {
    let decoded = decoded(file, ty, token.clone())?;
    let mut input = std::io::BufReader::new(super::cancel::Reader {
        inner: decoded.as_file(),
        token: token.clone(),
    });
    let staging = tempfile::Builder::new()
        .prefix(".ac-dc-incoming-")
        .tempdir_in(dest)?;
    let mut offset = 0u64;
    let mut total = 0;
    let mut files = 0;
    let mut clipboard = Vec::new();
    let mut clipboard_bytes = 0usize;
    let mut trailer = false;
    for _ in 0..MAX_ENTRIES {
        let mut magic = [0; 6];
        input
            .read_exact(&mut magic)
            .context("CPIO missing trailer")?;
        let (mode, size, namesize, align, hlen) = match &magic {
            b"070707" => {
                let mut h = [0; 70];
                input.read_exact(&mut h)?;
                (
                    number(&h[12..18], 8)?,
                    number(&h[59..70], 8)?,
                    number(&h[53..59], 8)?,
                    1,
                    76,
                )
            }
            b"070701" => {
                let mut h = [0; 104];
                input.read_exact(&mut h)?;
                (
                    number(&h[8..16], 16)?,
                    number(&h[48..56], 16)?,
                    number(&h[88..96], 16)?,
                    4,
                    110,
                )
            }
            _ => bail!("unsupported CPIO format"),
        };
        ensure!((1..=4096).contains(&namesize), "invalid CPIO name length");
        let mut name = vec![0; namesize as usize];
        input.read_exact(&mut name)?;
        ensure!(name.pop() == Some(0), "CPIO name not terminated");
        let name = std::str::from_utf8(&name)?;
        offset += hlen + namesize;
        pad(&mut input, &mut offset, align)?;
        if name == "TRAILER!!!" {
            ensure!(size == 0, "invalid CPIO trailer");
            trailer = true;
            break;
        }
        ensure!(size <= MAX_TRANSFER - total, "archive exceeds limit");
        total += size;
        if name == "." || name == "./" {
            ensure!(
                mode & 0o170000 == 0o040000 && size == 0,
                "invalid root entry"
            );
            continue;
        }
        let path = relative(name)?;
        let target = staging.path().join(&path);
        match mode & 0o170000 {
            0o040000 => {
                ensure!(size == 0, "directory has payload");
                std::fs::create_dir_all(&target)?;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))?;
            }
            0o100000 => {
                if path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("._")
                {
                    let n = std::io::copy(&mut input.by_ref().take(size), &mut std::io::sink())?;
                    ensure!(n == size, "truncated metadata");
                } else {
                    std::fs::create_dir_all(target.parent().unwrap())?;
                    let mut out = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&target)?;
                    let n = std::io::copy(&mut input.by_ref().take(size), &mut out)?;
                    ensure!(n == size, "truncated CPIO file");
                    out.sync_all()?;
                    files += 1;
                    // Clipboard copies stay small even when a transfer is many GiB.
                    if size <= 8 * 1024 * 1024
                        && clipboard_bytes + size as usize <= 8 * 1024 * 1024
                        && matches!(
                            path.extension().and_then(|s| s.to_str()),
                            Some("txt" | "png" | "jpg" | "jpeg" | "gif" | "webp")
                        )
                    {
                        let bytes = std::fs::read(&target)?;
                        clipboard_bytes += bytes.len();
                        clipboard.push(super::archive::Entry {
                            name: path.to_string_lossy().into(),
                            bytes,
                        });
                    }
                }
            }
            _ => bail!("archive links and special files are not supported"),
        }
        offset += size;
        pad(&mut input, &mut offset, align)?;
    }
    ensure!(trailer, "too many archive entries or missing trailer");
    ensure!(files > 0, "archive contains no regular files");
    token.check()?;
    // Publish top-level items directly into the selected receive directory, as
    // Airdrop-compatible does on macOS.  Never replace an existing item: Finder-style
    // collisions are numbered before the extension ("photo 2.jpg").
    use std::os::unix::ffi::OsStrExt;
    for entry in std::fs::read_dir(staging.path())? {
        let entry = entry?;
        let source = entry.path();
        let name = entry.file_name();
        let path = Path::new(&name);
        let stem = path.file_stem().unwrap_or(path.as_os_str());
        let extension = path.extension();
        let mut number = 1u64;
        loop {
            let candidate = if number == 1 {
                dest.join(&name)
            } else {
                let mut numbered = stem.to_os_string();
                numbered.push(format!(" {number}"));
                if let Some(extension) = extension {
                    numbered.push(".");
                    numbered.push(extension);
                }
                dest.join(numbered)
            };
            let old = std::ffi::CString::new(source.as_os_str().as_bytes())?;
            let new = std::ffi::CString::new(candidate.as_os_str().as_bytes())?;
            let rc = unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    old.as_ptr(),
                    libc::AT_FDCWD,
                    new.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if rc == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                number = number
                    .checked_add(1)
                    .context("too many filename collisions")?;
                continue;
            }
            return Err(error).context("publish transfer");
        }
    }
    File::open(dest)?.sync_all()?;
    Ok(Saved {
        directory: dest.to_path_buf(),
        files,
        bytes: total,
        clipboard,
    })
}
fn pad(input: &mut impl Read, offset: &mut u64, align: u64) -> Result<()> {
    let n = (align - (*offset % align)) % align;
    let mut b = [0; 3];
    input.read_exact(&mut b[..n as usize])?;
    *offset += n;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsafe_paths_rejected() {
        for p in [
            "/absolute",
            "../escape",
            "x/../../y",
            "a\\b",
            "\u{202e}hidden",
        ] {
            assert!(relative(p).is_err(), "{p}");
        }
        assert_eq!(
            relative("./folder/file.txt").unwrap(),
            PathBuf::from("folder/file.txt")
        );
    }
}
