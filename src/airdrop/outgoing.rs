//! Build a disk-backed DVZip/CPIO archive without loading selected files into RAM.
use anyhow::{ensure, Context, Result};
use plist::{Dictionary, Value};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
pub struct Prepared {
    pub metadata: Vec<Value>,
    pub archive: tempfile::NamedTempFile,
    pub bytes: u64,
}
fn header(out: &mut impl Write, name: &str, size: u64, mode: u32, ino: usize) -> Result<()> {
    ensure!(
        size <= 0o77777777777,
        "one file exceeds the 8 GiB CPIO odc limit"
    );
    write!(
        out,
        "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
        0,
        ino,
        mode,
        0,
        0,
        1,
        0,
        0,
        name.len() + 1,
        size
    )?;
    out.write_all(name.as_bytes())?;
    out.write_all(&[0])?;
    Ok(())
}
fn add(
    out: &mut impl Write,
    path: &Path,
    name: &str,
    count: &mut usize,
    total: &mut u64,
    depth: usize,
    token: &super::cancel::Token,
) -> Result<()> {
    token.check()?;
    ensure!(depth <= 64, "folder nesting exceeds limit");
    ensure!(name.len() <= 4095, "archive path too long");
    *count += 1;
    ensure!(*count < super::storage::MAX_ENTRIES, "too many files");
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() || meta.is_file(),
        "links and special files are not supported: {}",
        path.display()
    );
    if meta.is_dir() {
        header(out, name, 0, 0o040700, *count)?;
        let mut children = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        children.sort_by_key(|e| e.file_name());
        for child in children {
            let base = filename(&child.path())?;
            add(
                out,
                &child.path(),
                &format!("{name}/{base}"),
                count,
                total,
                depth + 1,
                token,
            )?;
        }
    } else {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        ensure!(meta.is_file(), "selected file changed type");
        ensure!(
            meta.len() <= super::storage::MAX_TRANSFER - *total,
            "transfer exceeds 32 GiB"
        );
        *total += meta.len();
        header(out, name, meta.len(), 0o100600, *count)?;
        let n = std::io::copy(
            &mut super::cancel::Reader {
                inner: std::io::Read::by_ref(&mut file).take(meta.len()),
                token: token.clone(),
            },
            out,
        )?;
        ensure!(n == meta.len(), "selected file changed during reading");
        ensure!(
            file.metadata()?.len() == meta.len(),
            "selected file changed during reading"
        );
    }
    Ok(())
}
fn filename(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("filename must be UTF-8")?;
    ensure!(
        name.len() <= 255
            && !name.chars().any(|c| c.is_control() || c == '\\')
            && name != "."
            && name != "..",
        "unsupported filename"
    );
    Ok(name.into())
}
#[cfg(test)]
pub fn prepare(paths: &[PathBuf]) -> Result<Prepared> {
    prepare_cancel(paths, super::cancel::Token::default())
}
pub fn prepare_cancel(paths: &[PathBuf], token: super::cancel::Token) -> Result<Prepared> {
    ensure!(
        !paths.is_empty() && paths.len() <= 4096,
        "choose between 1 and 4096 files or folders"
    );
    let mut cpio = tempfile::NamedTempFile::new()?;
    let mut metadata = Vec::new();
    let mut count = 0;
    let mut total = 0;
    let mut names = std::collections::HashSet::new();
    {
        for path in paths {
            let name = filename(path)?;
            ensure!(
                names.insert(name.clone()),
                "selected items have duplicate names"
            );
            let is_dir = std::fs::symlink_metadata(path)?.is_dir();
            let mut d = Dictionary::new();
            d.insert("FileName".into(), name.clone().into());
            d.insert("FileBomPath".into(), format!("./{name}").into());
            d.insert("FileIsDirectory".into(), is_dir.into());
            d.insert("ConvertMediaFormats".into(), 0.into());
            let ty = if is_dir {
                "public.folder"
            } else {
                match path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "png" => "public.png",
                    "jpg" | "jpeg" => "public.jpeg",
                    "txt" => "public.plain-text",
                    "pdf" => "com.adobe.pdf",
                    "mov" => "com.apple.quicktime-movie",
                    "mp4" => "public.mpeg-4",
                    _ => "public.data",
                }
            };
            d.insert("FileType".into(), ty.into());
            metadata.push(Value::Dictionary(d));
            add(
                cpio.as_file_mut(),
                path,
                &format!("./{name}"),
                &mut count,
                &mut total,
                0,
                &token,
            )?;
        }
        header(cpio.as_file_mut(), "TRAILER!!!", 0, 0, 0)?;
    }
    cpio.as_file_mut().rewind()?;
    let mut archive = tempfile::NamedTempFile::new()?;
    let mut block = vec![0u8; 128 * 1024];
    loop {
        token.check()?;
        let mut used = 0;
        while used < block.len() {
            let n = cpio.as_file_mut().read(&mut block[used..])?;
            if n == 0 {
                break;
            }
            used += n;
        }
        if used == 0 {
            break;
        }
        let mut compressed = Vec::new();
        {
            let mut encoder =
                flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::fast());
            encoder.write_all(&block[..used])?;
            encoder.finish()?;
        }
        ensure!(compressed.len() <= 0x7fff_ffff, "DVZip block exceeds limit");
        archive
            .as_file_mut()
            .write_all(&(compressed.len() as u32).to_be_bytes())?;
        archive.as_file_mut().write_all(&compressed)?;
    }
    let bytes = archive.as_file().metadata()?.len();
    ensure!(
        bytes <= super::storage::MAX_TRANSFER,
        "compressed transfer exceeds 32 GiB"
    );
    archive.as_file_mut().rewind()?;
    Ok(Prepared {
        metadata,
        archive,
        bytes,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn folder_roundtrip_and_atomic_rejection() {
        let source = tempfile::tempdir().unwrap();
        let folder = source.path().join("folder");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("hello.txt"), b"hello").unwrap();
        let p = prepare(&[folder]).unwrap();
        assert_eq!(
            p.metadata[0].as_dictionary().unwrap()["FileIsDirectory"].as_boolean(),
            Some(true)
        );
        let dest = tempfile::tempdir().unwrap();
        let saved = super::super::storage::receive(
            p.archive.reopen().unwrap(),
            "application/x-dvzip",
            dest.path(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(saved.directory.join("folder/hello.txt")).unwrap(),
            b"hello"
        );
        let mut bad = tempfile::tempfile().unwrap();
        header(&mut bad, "../escape", 1, 0o100600, 1).unwrap();
        bad.write_all(b"x").unwrap();
        bad.rewind().unwrap();
        assert!(super::super::storage::receive(bad, "application/x-cpio", dest.path()).is_err());
        assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 1);
    }
    #[test]
    fn receive_uses_base_directory_and_numbers_collisions() {
        let source = tempfile::tempdir().unwrap();
        let file = source.path().join("photo.jpg");
        std::fs::write(&file, b"new").unwrap();
        let p = prepare(&[file]).unwrap();
        let dest = tempfile::tempdir().unwrap();
        std::fs::write(dest.path().join("photo.jpg"), b"old").unwrap();
        std::fs::write(dest.path().join("photo 2.jpg"), b"older").unwrap();
        let saved = super::super::storage::receive(
            p.archive.reopen().unwrap(),
            "application/x-dvzip",
            dest.path(),
        )
        .unwrap();
        assert_eq!(saved.directory, dest.path());
        assert_eq!(
            std::fs::read(dest.path().join("photo.jpg")).unwrap(),
            b"old"
        );
        assert_eq!(
            std::fs::read(dest.path().join("photo 3.jpg")).unwrap(),
            b"new"
        );
    }
    #[test]
    fn sends_beyond_old_memory_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(65 * 1024 * 1024).unwrap();
        let p = prepare(&[path]).unwrap();
        let dest = tempfile::tempdir().unwrap();
        let saved = super::super::storage::receive(
            p.archive.reopen().unwrap(),
            "application/x-dvzip",
            dest.path(),
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(saved.directory.join("large.bin"))
                .unwrap()
                .len(),
            65 * 1024 * 1024
        );
    }
}

#[cfg(test)]
mod reference_tests {
    use super::*;
    #[test]
    fn canonical_odc_trailer() {
        let mut bytes = Vec::new();
        header(&mut bytes, "TRAILER!!!", 0, 0, 0).unwrap();
        assert_eq!(bytes, b"0707070000000000000000000000000000000000010000000000000000000001300000000000TRAILER!!!\0");
    }
    #[test]
    #[ignore = "requires bsdtar (libarchive), run explicitly for interoperability checks"]
    fn libarchive_extracts_rust_archive() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("sample.txt");
        std::fs::write(&file, b"independent archive decoder fixture").unwrap();
        let archive = prepare(&[file]).unwrap();
        let cpio =
            super::super::archive::dvzip(&std::fs::read(archive.archive.path()).unwrap()).unwrap();
        let mut decoded = tempfile::NamedTempFile::new().unwrap();
        decoded.write_all(&cpio).unwrap();
        let out = std::process::Command::new("bsdtar")
            .arg("-xOf")
            .arg(decoded.path())
            .arg("./sample.txt")
            .output()
            .expect("install libarchive/bsdtar for this interoperability test");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"independent archive decoder fixture");
    }
}
