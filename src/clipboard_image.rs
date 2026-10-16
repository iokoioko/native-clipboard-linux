//! Bounded typed inline clipboard selection. No clipboard or filesystem access.
use anyhow::{ensure, Result};
pub const TEXT_MIME: &str = "text/plain;charset=utf-8";
pub const PNG_MIME: &str = "image/png";
pub const MAX_PNG_BYTES: usize = 1024 * 1024;
const MAX_PIXELS: u64 = 16_000_000;
const MAX_DECODED: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Png,
}
impl Kind {
    pub fn mime(self) -> &'static str {
        match self {
            Self::Text => TEXT_MIME,
            Self::Png => PNG_MIME,
        }
    }
    pub fn uti(self) -> &'static str {
        match self {
            Self::Text => "public.utf8-plain-text",
            Self::Png => "public.png",
        }
    }
}
pub struct Inline<'a> {
    pub kind: Kind,
    pub bytes: &'a [u8],
}
/// Prefer native UTF-8 text, then PNG. Unknown representations are never copied.
pub fn representation(
    board: &crate::clipboard::DecodedPasteboard,
) -> Option<(Kind, &crate::clipboard::Representation)> {
    [Kind::Text, Kind::Png].into_iter().find_map(|kind| {
        board
            .representations
            .iter()
            .find(|r| r.uti == kind.uti())
            .map(|r| (kind, r))
    })
}
/// PNG requires complete generation identity; text retains missing-UUID/size compatibility.
pub fn generation_matches(
    kind: Option<Kind>,
    provider: Option<[u8; 16]>,
    size: Option<u64>,
    board: &crate::clipboard::DecodedPasteboard,
) -> bool {
    let Some((actual, rep)) = representation(board) else {
        return false;
    };
    if kind != Some(actual) {
        return false;
    }
    match actual {
        Kind::Png => {
            provider.is_some() && provider == rep.provider_id && size.is_some() && size == rep.size
        }
        Kind::Text => {
            provider.is_none_or(|id| rep.provider_id == Some(id))
                && size.is_none_or(|length| rep.size == Some(length))
        }
    }
}
pub fn inline(board: &crate::clipboard::DecodedPasteboard) -> Option<Inline<'_>> {
    if board.extra_data_type != Some(2) {
        return None;
    }
    let (kind, rep) = representation(board)?;
    let bytes = rep.data.as_deref()?;
    if rep.size.is_some_and(|size| size != bytes.len() as u64)
        || (kind == Kind::Png && rep.size.is_none())
    {
        return None;
    }
    match kind {
        Kind::Text => {
            std::str::from_utf8(bytes).ok()?;
        }
        Kind::Png => {
            validate_png(bytes).ok()?;
        }
    }
    Some(Inline { kind, bytes })
}
/// Decode a static PNG fully with CRC checking and explicit allocation/pixel caps.
/// Pass through the original bytes; no raster is retained or re-encoded.
pub fn validate_png(bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PNG_BYTES,
        "PNG byte limit"
    );
    let mut decoder = png::Decoder::new_with_limits(
        std::io::Cursor::new(bytes),
        png::Limits { bytes: MAX_DECODED },
    );
    decoder.ignore_checksums(false);
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    let mut reader = decoder.read_info()?;
    let info = reader.info();
    ensure!(!info.is_animated(), "animated PNG unsupported");
    ensure!(
        info.width != 0
            && info.height != 0
            && u64::from(info.width) * u64::from(info.height) <= MAX_PIXELS,
        "PNG pixel limit"
    );
    let output = reader.output_buffer_size();
    ensure!(output <= MAX_DECODED, "PNG decoded byte limit");
    let mut raster = vec![0; output];
    reader.next_frame(&mut raster)?;
    reader.finish()?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub fn png() -> Vec<u8> {
        hex::decode("89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c49444154789c63f8cfc0000003010100c9fe92ef0000000049454e44ae426082").unwrap()
    }
    #[test]
    fn native_model_png_archive_yields_valid_exact_image_bytes() {
        let fixture = include_bytes!("../tests/fixtures/foundation-macos15-clipboard.bplist");
        // Actual PNG archive comes from the encoder whose image model passed the
        // independent native decoder oracle, not a captured user clipboard.
        let bytes = png();
        let archive = crate::clipboard_serve::encode_representation_archive(
            Some(crate::clipboard_serve::RepresentationSnapshot {
                uti: "public.png",
                bytes: &bytes,
                provider_id: [0x50; 16],
            }),
            crate::clipboard_serve::ArchiveKind::InlineData,
        )
        .unwrap();
        let board = crate::clipboard::decode_pasteboard_archive(&archive).unwrap();
        let selected = inline(&board).unwrap();
        assert!(selected.kind == Kind::Png);
        assert_eq!(selected.bytes, bytes);
        assert!(crate::clipboard::decode_pasteboard_archive(fixture).is_ok());
    }
    #[test]
    fn image_provider_and_size_must_match_but_missing_text_metadata_stays_compatible() {
        let bytes = png();
        let archive = crate::clipboard_serve::encode_representation_archive(
            Some(crate::clipboard_serve::RepresentationSnapshot {
                uti: "public.png",
                bytes: &bytes,
                provider_id: [0x50; 16],
            }),
            crate::clipboard_serve::ArchiveKind::InlineData,
        )
        .unwrap();
        let mut board = crate::clipboard::decode_pasteboard_archive(&archive).unwrap();
        assert!(generation_matches(
            Some(Kind::Png),
            Some([0x50; 16]),
            Some(bytes.len() as u64),
            &board
        ));
        assert!(!generation_matches(
            Some(Kind::Png),
            None,
            Some(bytes.len() as u64),
            &board
        ));
        assert!(!generation_matches(
            Some(Kind::Png),
            Some([0x51; 16]),
            Some(bytes.len() as u64),
            &board
        ));
        assert!(!generation_matches(
            Some(Kind::Png),
            Some([0x50; 16]),
            Some(1),
            &board
        ));
        board.representations[0].uti = "public.utf8-plain-text".into();
        board.representations[0].data = Some(b"text".to_vec());
        board.representations[0].size = None;
        assert!(generation_matches(Some(Kind::Text), None, None, &board));
        assert!(inline(&board).is_some());
    }
    #[test]
    fn rejects_crc_corruption_truncation_and_oversized_or_non_png_data() {
        let good = png();
        validate_png(&good).unwrap();
        for length in [0, 8, 32, good.len() - 1] {
            assert!(validate_png(&good[..length]).is_err());
        }
        let mut corrupt = good.clone();
        corrupt[45] ^= 1;
        assert!(validate_png(&corrupt).is_err());
        assert!(validate_png(b"not PNG").is_err());
        assert!(validate_png(&vec![0; MAX_PNG_BYTES + 1]).is_err());
    }
    #[test]
    fn rejects_valid_png_with_excessive_pixel_dimensions() {
        let mut output = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut output, 4001, 4001);
            encoder.set_color(png::ColorType::Grayscale);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&vec![0; 4001 * 4001]).unwrap();
        }
        assert!(validate_png(&output)
            .unwrap_err()
            .to_string()
            .contains("pixel limit"));
    }
    #[test]
    fn stream_type_or_mislabeled_text_is_never_an_image() {
        let bytes = png();
        let archive = crate::clipboard_serve::encode_representation_archive(
            Some(crate::clipboard_serve::RepresentationSnapshot {
                uti: "public.png",
                bytes: &bytes,
                provider_id: [0x50; 16],
            }),
            crate::clipboard_serve::ArchiveKind::InlineData,
        )
        .unwrap();
        let mut board = crate::clipboard::decode_pasteboard_archive(&archive).unwrap();
        board.extra_data_type = Some(1);
        assert!(inline(&board).is_none());
        board.extra_data_type = Some(2);
        board.representations[0].data = Some(b"text".to_vec());
        assert!(inline(&board).is_none());
    }
}
