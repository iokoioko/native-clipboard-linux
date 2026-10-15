//! Bounded DVZip/gzip and CPIO decoding. Extract regular files into one directory only.
#[cfg(test)]
use anyhow::bail;
use anyhow::{ensure, Context, Result};
#[cfg(test)]
use std::io::Read;
use std::{
    fs,
    path::{Path, PathBuf},
};
#[cfg(test)]
const MAX: usize = 64 * 1024 * 1024;
#[cfg(test)]
fn inflate(reader: impl Read, remaining: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    reader.take(remaining as u64 + 1).read_to_end(&mut b)?;
    ensure!(b.len() <= remaining, "decompressed upload exceeds limit");
    Ok(b)
}
#[cfg(test)]
pub fn dvzip(b: &[u8]) -> Result<Vec<u8>> {
    if b.starts_with(&[31, 139]) {
        return inflate(flate2::read::GzDecoder::new(b), MAX);
    }
    let mut off = 0;
    let mut out = Vec::new();
    while off < b.len() {
        let hdr = u32::from_be_bytes(
            b.get(off..off + 4)
                .context("truncated DVZip header")?
                .try_into()?,
        );
        off += 4;
        let n = (hdr & 0x7fff_ffff) as usize;
        ensure!(n > 0, "empty DVZip block");
        let block = b.get(off..off + n).context("truncated DVZip block")?;
        off += n;
        if hdr & 0x8000_0000 != 0 {
            ensure!(
                block.len() <= MAX - out.len(),
                "upload exceeds decoded limit"
            );
            out.extend(block);
        } else {
            out.extend(inflate(
                flate2::read::ZlibDecoder::new(block),
                MAX - out.len(),
            )?);
        }
    }
    Ok(out)
}
#[cfg(test)]
fn number(b: &[u8], radix: u32) -> Result<usize> {
    Ok(usize::from_str_radix(std::str::from_utf8(b)?, radix)?)
}
#[derive(Debug)]
pub struct Entry {
    pub name: String,
    pub bytes: Vec<u8>,
}
#[cfg(test)]
pub fn cpio(b: &[u8]) -> Result<Vec<Entry>> {
    ensure!(b.len() <= MAX, "archive exceeds decoded limit");
    let mut off = 0;
    let mut out = Vec::new();
    let mut count = 0;
    loop {
        count += 1;
        ensure!(count <= 4096, "too many archive entries");
        let magic = b.get(off..off + 6).context("CPIO missing trailer")?;
        let (header, mode, size, namesize, align) = match magic {
            b"070707" => {
                let h = b.get(off..off + 76).context("short odc header")?;
                (
                    76,
                    number(&h[18..24], 8)?,
                    number(&h[65..76], 8)?,
                    number(&h[59..65], 8)?,
                    1,
                )
            }
            b"070701" => {
                let h = b.get(off..off + 110).context("short newc header")?;
                (
                    110,
                    number(&h[14..22], 16)?,
                    number(&h[54..62], 16)?,
                    number(&h[94..102], 16)?,
                    4,
                )
            }
            _ => bail!("unsupported CPIO format"),
        };
        ensure!((1..=4096).contains(&namesize), "bad CPIO name length");
        off += header;
        let name = b.get(off..off + namesize).context("truncated CPIO name")?;
        ensure!(name.last() == Some(&0), "CPIO filename must end in NUL");
        let name = std::str::from_utf8(&name[..name.len() - 1])?;
        off = (off + namesize + align - 1) & !(align - 1);
        let data = b.get(off..off + size).context("truncated CPIO payload")?;
        off = (off + size + align - 1) & !(align - 1);
        if name == "TRAILER!!!" {
            ensure!(size == 0, "invalid CPIO trailer");
            break;
        }
        let base = name.rsplit(['/', '\\']).next().unwrap_or("");
        if mode & 0o170000 == 0o100000 && !base.starts_with("._") {
            out.push(Entry {
                name: safe_name(base)?,
                bytes: data.to_vec(),
            });
        }
    }
    Ok(out)
}
pub fn safe_name(name: &str) -> Result<String> {
    let s = name.rsplit(['/', '\\']).next().unwrap_or("");
    let s: String = s
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
        .collect();
    let mut s = s.trim().trim_start_matches('.').to_string();
    while s.len() > 200 {
        s.pop();
    }
    ensure!(!s.is_empty(), "empty received filename");
    Ok(s)
}
pub fn store(dest: &Path, entries: &[Entry]) -> Result<Vec<PathBuf>> {
    use std::io::Write;
    let mut written = Vec::new();
    let result = (|| -> Result<()> {
        for e in entries {
            let base = safe_name(&e.name)?;
            let mut temporary = tempfile::NamedTempFile::new_in(dest)?;
            temporary.write_all(&e.bytes)?;
            temporary.as_file().sync_all()?;
            let mut saved = false;
            for i in 0..1000 {
                let name = if i == 0 {
                    base.clone()
                } else {
                    let p = Path::new(&base);
                    let stem = p.file_stem().context("filename stem")?.to_string_lossy();
                    match p.extension() {
                        Some(ext) => format!("{stem}-{i}.{}", ext.to_string_lossy()),
                        None => format!("{stem}-{i}"),
                    }
                };
                let path = dest.join(name);
                match temporary.persist_noclobber(&path) {
                    Ok(_) => {
                        written.push(path);
                        saved = true;
                        break;
                    }
                    Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => {
                        temporary = err.file;
                    }
                    Err(err) => return Err(err.error.into()),
                }
            }
            ensure!(saved, "too many filename collisions");
        }
        Ok(())
    })();
    if let Err(e) = result {
        for p in &written {
            let _ = fs::remove_file(p);
        }
        return Err(e);
    }
    Ok(written)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stored_and_truncated_dvzip() {
        assert_eq!(dvzip(&[0x80, 0, 0, 3, 1, 2, 3]).unwrap(), [1, 2, 3]);
        for b in [&[0u8, 0, 0][..], &[0x80, 0, 0, 4, 1][..]] {
            assert!(dvzip(b).is_err());
        }
    }
    #[test]
    fn paths() {
        assert_eq!(safe_name("../../日本語.jpg").unwrap(), "日本語.jpg");
        assert_eq!(safe_name("C:\\x\\photo.jpg").unwrap(), "photo.jpg");
        assert!(safe_name("..").is_err());
    }
    #[test]
    fn limits() {
        assert!(cpio(b"070707").is_err());
        assert!(dvzip(&[0, 0, 0, 0]).is_err());
    }
}

#[cfg(test)]
mod compression_tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn mixed_stored_and_zlib_blocks_and_gzip() {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"hello").unwrap();
        let z = z.finish().unwrap();
        let mut b = (z.len() as u32).to_be_bytes().to_vec();
        b.extend(z);
        b.extend([0x80, 0, 0, 1, b'!']);
        assert_eq!(dvzip(&b).unwrap(), b"hello!");
        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        g.write_all(b"gzip").unwrap();
        assert_eq!(dvzip(&g.finish().unwrap()).unwrap(), b"gzip");
        assert!(inflate(&b"too many decoded bytes"[..], 4).is_err());
    }
}
