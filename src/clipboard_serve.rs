//! Offline Universal Clipboard archive encoder; this does not advertise or send.
//!
//! The model keys follow the native macOS 15.7 serializers. Peer acceptance is
//! not established by local decoding. The caller owns provider identity and must
//! retain it for both requests concerning the same copy.

use anyhow::{ensure, Result};
use plist::{Dictionary, Uid, Value};

/// Deliberately limited to small inline text, leaving headroom below the reader's
/// archive limit. This is a local policy, not a claimed Apple protocol limit.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
pub const UTF8_TEXT_UTI: &str = "public.utf8-plain-text";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveKind {
    Types,
    InlineData,
}

/// A snapshot borrowed from the caller; constructing/encoding it never reads the
/// system clipboard and never generates or replaces its provider UUID.
#[derive(Clone, Copy, Debug)]
pub struct TextSnapshot<'a> {
    pub text: &'a str,
    pub provider_id: [u8; 16],
}

/// Encode one text representation, or an unavailable wrapper when `None`.
/// `Types` carries a null offset and no blob; `InlineData` carries offset zero
/// and the exact UTF-8 bytes (without an added terminator).
pub fn encode_text_archive(
    snapshot: Option<TextSnapshot<'_>>,
    kind: ArchiveKind,
) -> Result<Vec<u8>> {
    if let Some(snapshot) = snapshot {
        ensure!(
            snapshot.text.len() <= MAX_TEXT_BYTES,
            "clipboard text exceeds inline byte limit"
        );
    }
    let mut graph = Graph(vec![Value::String("$null".into())]);
    let wrapper_class = graph.class("UASharedPasteboardInfoWrapper");
    let mut info = null();
    let mut extra = null();
    let mut extra_type = 0u64;
    if let Some(snapshot) = snapshot {
        let info_class = graph.class("UASharedPasteboardInfo");
        let item_class = graph.class("UASharedPasteboardItemInfo");
        let type_class = graph.class("UASharedPasteboardTypeInfo");
        let array_class = graph.class("NSArray");
        let dict_class = graph.class("NSDictionary");
        let uuid_class = graph.class("NSUUID");
        let uuid = graph.object(
            uuid_class,
            [("NS.uuidbytes", Value::Data(snapshot.provider_id.to_vec()))],
        );
        let uti = graph.add(UTF8_TEXT_UTI.into());
        let index = graph.add(0u64.into());
        let offset = if kind == ArchiveKind::InlineData {
            graph.add(0u64.into())
        } else {
            null()
        };
        let type_info = graph.object(
            type_class,
            [
                ("UASharedPasteboardTypeInfoTypeKey", uti.clone()),
                ("UASharedPasteboardTypeInfoUUIDKey", uuid),
                ("UASharedPasteboardTypeInfoOffsetKey", offset),
                (
                    "UASharedPasteboardTypeInfoSizeKey",
                    (snapshot.text.len() as u64).into(),
                ),
                ("UASharedPasteboardTypeInfoIndex", index),
                ("UASharedPasteboardTypeInfoDataFileKey", null()),
                ("UASharedPasteboardTypeInfoPrefRepKey", false.into()),
                ("UASharedPasteboardTypeInfoTypeHintKey", null()),
            ],
        );
        let types = graph.object(
            dict_class,
            [
                ("NS.keys", Value::Array(vec![uti])),
                ("NS.objects", Value::Array(vec![type_info])),
            ],
        );
        let item = graph.object(item_class, [("UASharedPasteboardItemInfoTypesKey", types)]);
        let items = graph.object(array_class, [("NS.objects", Value::Array(vec![item]))]);
        info = graph.object(
            info_class,
            [
                ("UASharedPasteboardInfoItemsKey", items),
                (
                    "UASharedPasteboardInfoDataSizeKey",
                    (snapshot.text.len() as u64).into(),
                ),
                ("UASharedPasteboardInfoDataFileKey", null()),
                ("UASharedPasteboardInfoDataPathKey", null()),
                ("UASharedPasteboardInfoExtensionKey", null()),
            ],
        );
        if kind == ArchiveKind::InlineData {
            extra = graph.add(Value::Data(snapshot.text.as_bytes().to_vec()));
            extra_type = 2;
        }
    }
    let wrapper = graph.object(
        wrapper_class,
        [
            ("UASharedPasteboardInfoWrapperPBInfoKey", info),
            ("UASharedPasteboardInfoWrapperExtraDataKey", extra),
            (
                "UASharedPasteboardInfoWrapperExtraTypeKey",
                extra_type.into(),
            ),
            ("UASharedPasteboardInfoWrapperErrorKey", null()),
            (
                "UASharedPasteboardInfoWrapperProtocolVersionKey",
                match kind {
                    ArchiveKind::Types => 2u64,
                    ArchiveKind::InlineData => 0u64,
                }
                .into(),
            ),
        ],
    );
    let archive = dictionary([
        ("$archiver", "NSKeyedArchiver".into()),
        ("$version", 100_000u64.into()),
        ("$objects", Value::Array(graph.0)),
        ("$top", dictionary([("root", wrapper)])),
    ]);
    let mut bytes = Vec::new();
    archive.to_writer_binary(&mut bytes)?;
    Ok(bytes)
}

fn null() -> Value {
    Value::Uid(Uid::new(0))
}
fn dictionary<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Dictionary(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<Dictionary>(),
    )
}
struct Graph(Vec<Value>);
impl Graph {
    fn add(&mut self, value: Value) -> Value {
        let id = self.0.len() as u64;
        self.0.push(value);
        Value::Uid(Uid::new(id))
    }
    fn class(&mut self, name: &str) -> Value {
        self.add(dictionary([
            ("$classname", name.into()),
            (
                "$classes",
                Value::Array(vec![name.into(), "NSObject".into()]),
            ),
        ]))
    }
    fn object<const N: usize>(&mut self, class: Value, entries: [(&str, Value); N]) -> Value {
        let mut d = match dictionary(entries) {
            Value::Dictionary(d) => d,
            _ => unreachable!(),
        };
        d.insert("$class".into(), class);
        self.add(Value::Dictionary(d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::decode_pasteboard_archive;

    #[test]
    fn metadata_and_inline_share_provider_and_use_utf8_byte_lengths() {
        let snapshot = TextSnapshot {
            text: "copié 🦀",
            provider_id: [0x42; 16],
        };
        let metadata = decode_pasteboard_archive(
            &encode_text_archive(Some(snapshot), ArchiveKind::Types).unwrap(),
        )
        .unwrap();
        let content = decode_pasteboard_archive(
            &encode_text_archive(Some(snapshot), ArchiveKind::InlineData).unwrap(),
        )
        .unwrap();
        assert_eq!(metadata.extra_data_type, Some(0));
        assert_eq!(content.extra_data_type, Some(2));
        assert_eq!(metadata.protocol_version, Some(2));
        assert_eq!(content.protocol_version, Some(0));
        for decoded in [&metadata, &content] {
            assert_eq!(decoded.data_size, Some(snapshot.text.len() as u64));
            assert_eq!(decoded.representations.len(), 1);
            let rep = &decoded.representations[0];
            assert_eq!(rep.uti, UTF8_TEXT_UTI);
            assert_eq!(rep.provider_id, Some(snapshot.provider_id));
            assert_eq!(rep.size, Some(snapshot.text.len() as u64));
        }
        assert_eq!(metadata.representations[0].offset, None);
        assert_eq!(metadata.representations[0].data, None);
        assert_eq!(content.representations[0].offset, Some(0));
        assert_eq!(
            content.representations[0].data.as_deref(),
            Some(snapshot.text.as_bytes())
        );
    }

    #[test]
    fn repeat_requests_preserve_identity_and_new_copy_can_change_it() {
        let snapshot = TextSnapshot {
            text: "same text",
            provider_id: [1; 16],
        };
        let first = encode_text_archive(Some(snapshot), ArchiveKind::Types).unwrap();
        assert_eq!(
            first,
            encode_text_archive(Some(snapshot), ArchiveKind::Types).unwrap()
        );
        let next = TextSnapshot {
            provider_id: [2; 16],
            ..snapshot
        };
        let decoded = decode_pasteboard_archive(
            &encode_text_archive(Some(next), ArchiveKind::InlineData).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded.representations[0].provider_id, Some([2; 16]));
    }

    #[test]
    fn rejects_oversized_utf8_for_both_kinds() {
        let text = "é".repeat(MAX_TEXT_BYTES / 2 + 1);
        for kind in [ArchiveKind::Types, ArchiveKind::InlineData] {
            assert!(encode_text_archive(
                Some(TextSnapshot {
                    text: &text,
                    provider_id: [1; 16]
                }),
                kind
            )
            .is_err());
        }
    }

    #[test]
    fn unavailable_is_distinct_from_available_empty_text() {
        for kind in [ArchiveKind::Types, ArchiveKind::InlineData] {
            let unavailable = encode_text_archive(None, kind).unwrap();
            assert_eq!(
                decode_pasteboard_archive(&unavailable)
                    .unwrap_err()
                    .to_string(),
                "clipboard archive contains no pasteboard info"
            );
        }
        let empty = encode_text_archive(
            Some(TextSnapshot {
                text: "",
                provider_id: [3; 16],
            }),
            ArchiveKind::InlineData,
        )
        .unwrap();
        let decoded = decode_pasteboard_archive(&empty).unwrap();
        assert_eq!(decoded.representations[0].data.as_deref(), Some(&b""[..]));
    }

    /// Explicit offline export for a native decoder oracle. No clipboard reads.
    #[test]
    #[ignore = "requires explicit synthetic fixture output directory"]
    fn export_native_oracle_fixtures() {
        use std::io::Write;
        let dir = std::path::PathBuf::from(
            std::env::var_os("AC_DC_ARCHIVE_OUTPUT_DIR")
                .expect("set AC_DC_ARCHIVE_OUTPUT_DIR to an existing directory"),
        );
        assert!(dir.is_dir(), "fixture output directory must already exist");
        let snapshot = TextSnapshot {
            text: "native reverse fixture 47",
            provider_id: [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        };
        for (name, kind) in [
            ("reverse-synthetic-types.bplist", ArchiveKind::Types),
            ("reverse-synthetic-inline.bplist", ArchiveKind::InlineData),
        ] {
            let bytes = encode_text_archive(Some(snapshot), kind).unwrap();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))
                .expect("fixture must not already exist");
            file.write_all(&bytes).unwrap();
        }
    }
}
