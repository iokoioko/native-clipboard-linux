//! Universal Clipboard request envelopes and a bounded NSKeyedArchiver reader.
//!
//! The request names and keys here are taken from the historical
//! `UniversalClipboardController.swift` reference. Advertisement payload bytes
//! are supplied by the caller because their value is generation and operation
//! specific; this module does not synthesize them.
//!
//! Keyed archives are parsed as inert property-list graphs. No archived class
//! is instantiated, and only the small set of classes needed to recover inline
//! pasteboard data is accepted.

use anyhow::{bail, ensure, Context, Result};
use plist::{Dictionary, Value as PlistValue};
use std::io::Cursor;

use crate::opack::Value;

pub const SELECTOR_SYSTEM_INFO: &str = "_systemInfo";
pub const SELECTOR_PAYLOAD_REQUEST: &str = "com.apple.handoff.payload-request";
pub const COMMAND_PB_TYPES: &str = "pbtypes";
pub const COMMAND_PB_PASTE2: &str = "pbpaste2";

const KEY_TYPE: &str = "_t";
const KEY_SELECTOR: &str = "_i";
const KEY_REQUEST_ID: &str = "_x";
const KEY_CONTENT: &str = "_c";
const KEY_REMOTE_ERROR: &str = "_em";
const KEY_COMMAND: &str = "rClientCommand";
const KEY_IDENTIFIER: &str = "rIdentifier";
const KEY_ADVERTISEMENT: &str = "rAdvPayload";
const KEY_ARCHIVE: &str = "rActPayload";

const REQUEST_TYPE: u64 = 2;
const RESPONSE_TYPE: u64 = 3;
const MAX_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ARCHIVE_OBJECTS: usize = 100_000;
const MAX_ITEMS: usize = 256;
const MAX_REPRESENTATIONS: usize = 1024;

/// Build the historical system-info request envelope. The `_c` value is
/// supplied by the caller because device metadata belongs to the local peer.
pub fn build_system_info_request(request_id: u64, system_info: Value) -> Result<Value> {
    ensure!(
        matches!(&system_info, Value::Dict(_)),
        "system-info content must be an OPACK dictionary"
    );
    Ok(Value::dict([
        (KEY_TYPE, Value::Int(REQUEST_TYPE)),
        (KEY_SELECTOR, Value::Str(SELECTOR_SYSTEM_INFO.into())),
        (KEY_REQUEST_ID, Value::Int(request_id)),
        (KEY_CONTENT, system_info),
    ]))
}

/// Build the observed payload-request envelope. `advertisement_payload` must
/// come from a captured or otherwise validated source for this request.
pub fn build_payload_request(
    request_id: u64,
    command: &str,
    identifier: &str,
    advertisement_payload: &[u8],
) -> Result<Value> {
    ensure!(
        matches!(command, COMMAND_PB_TYPES | COMMAND_PB_PASTE2),
        "unsupported clipboard command {command:?}"
    );
    ensure!(!identifier.is_empty(), "clipboard identifier is empty");

    Ok(Value::dict([
        (KEY_TYPE, Value::Int(REQUEST_TYPE)),
        (KEY_SELECTOR, Value::Str(SELECTOR_PAYLOAD_REQUEST.into())),
        (KEY_REQUEST_ID, Value::Int(request_id)),
        (
            KEY_CONTENT,
            Value::dict([
                (KEY_COMMAND, Value::Str(command.into())),
                (KEY_IDENTIFIER, Value::Str(identifier.into())),
                (
                    KEY_ADVERTISEMENT,
                    Value::Bytes(advertisement_payload.to_vec()),
                ),
            ]),
        ),
    ]))
}

/// Result of validating a payload-request response envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadResponse {
    /// The historical controller handles `_em` as a top-level remote error.
    RemoteError(String),
    /// Raw `rActPayload` bytes containing an NSKeyedArchiver plist.
    Archive(Vec<u8>),
}

/// Validate the response type and transaction id, then extract the observed
/// `rActPayload` field. Responses without a payload may be remote errors; other
/// shapes are rejected rather than interpreted as clipboard data.
pub fn validate_payload_response(value: &Value, expected_id: u64) -> Result<PayloadResponse> {
    ensure!(
        value.get(KEY_TYPE).and_then(Value::as_u64) == Some(RESPONSE_TYPE),
        "clipboard response `_t` is not 3"
    );
    ensure!(
        value.get(KEY_REQUEST_ID).and_then(Value::as_u64) == Some(expected_id),
        "clipboard response `_x` does not match request id"
    );
    if let Some(error) = value.get(KEY_REMOTE_ERROR) {
        let error = error
            .as_str()
            .context("clipboard response `_em` is not a string")?;
        return Ok(PayloadResponse::RemoteError(error.to_string()));
    }
    let content = value
        .get(KEY_CONTENT)
        .context("clipboard response missing `_c`")?;
    let archive = content
        .get(KEY_ARCHIVE)
        .and_then(Value::as_bytes)
        .context("clipboard response `_c.rActPayload` is not bytes")?;
    ensure!(
        archive.len() <= MAX_ARCHIVE_BYTES,
        "clipboard archive exceeds {MAX_ARCHIVE_BYTES} byte cap"
    );
    Ok(PayloadResponse::Archive(archive.to_vec()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Representation {
    /// Provider identity candidate; not yet used for copy ordering.
    pub provider_id: Option<[u8; 16]>,
    /// The UTI named by the type-info object's `...TypeKey` field.
    pub uti: String,
    /// Offset of this representation in wrapper `extraData`, when present.
    pub offset: Option<u64>,
    /// Byte length from the type-info object's size field, when present.
    pub size: Option<u64>,
    /// Inline bytes selected by offset and size. `None` means this archive only
    /// carries pasteboard type metadata or references an unsupported bulk path.
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecodedPasteboard {
    pub representations: Vec<Representation>,
    pub extra_data_type: Option<u64>,
    pub data_size: Option<u64>,
    pub protocol_version: Option<u64>,
}

/// Decode the historical `UASharedPasteboardInfoWrapper` archive shape without
/// executing or instantiating archived classes. Only inline data represented
/// by a type-info offset and size is returned. File-handle-backed types are
/// not followed by this prototype.
pub fn decode_pasteboard_archive(bytes: &[u8]) -> Result<DecodedPasteboard> {
    ensure!(!bytes.is_empty(), "clipboard archive is empty");
    ensure!(
        bytes.len() <= MAX_ARCHIVE_BYTES,
        "clipboard archive exceeds {MAX_ARCHIVE_BYTES} byte cap"
    );
    let root =
        PlistValue::from_reader(Cursor::new(bytes)).context("parsing keyed archive plist")?;
    let dict = root
        .as_dictionary()
        .context("keyed archive root is not a dictionary")?;
    ensure!(
        dict.get("$archiver").and_then(PlistValue::as_string) == Some("NSKeyedArchiver"),
        "plist is not an NSKeyedArchiver archive"
    );
    let objects = dict
        .get("$objects")
        .and_then(PlistValue::as_array)
        .context("keyed archive has no `$objects` array")?;
    ensure!(
        objects.len() <= MAX_ARCHIVE_OBJECTS,
        "keyed archive has too many objects"
    );
    let top = dict
        .get("$top")
        .and_then(PlistValue::as_dictionary)
        .context("keyed archive has no `$top` dictionary")?;
    let root_ref = top.get("root").context("keyed archive has no `root`")?;
    let graph = ArchiveGraph { objects };
    let wrapper = graph.object_dict(root_ref, "UASharedPasteboardInfoWrapper")?;

    if let Some(error) = wrapper.get("UASharedPasteboardInfoWrapperErrorKey") {
        if !graph.is_null(error)? {
            graph.expect_class(error, "NSError")?;
            bail!("clipboard archive contains a remote NSError");
        }
    }

    let extra_data_type = wrapper
        .get("UASharedPasteboardInfoWrapperExtraTypeKey")
        .map(|value| graph.integer(value))
        .transpose()?;
    let version = wrapper
        .get("UASharedPasteboardInfoWrapperProtocolVersionKey")
        .map(|value| graph.integer(value))
        .transpose()?;
    let extra_data = match wrapper.get("UASharedPasteboardInfoWrapperExtraDataKey") {
        Some(value) if graph.is_null(value)? => None,
        Some(value) => Some(graph.data(value)?),
        None => None,
    };
    let pb_info_ref = wrapper
        .get("UASharedPasteboardInfoWrapperPBInfoKey")
        .context("wrapper is missing pasteboard info")?;
    ensure!(
        !graph.is_null(pb_info_ref)?,
        "clipboard archive contains no pasteboard info"
    );
    let pb_info = graph.object_dict(pb_info_ref, "UASharedPasteboardInfo")?;
    let data_size = pb_info
        .get("UASharedPasteboardInfoDataSizeKey")
        .map(|value| graph.integer(value))
        .transpose()?;
    if let Some(file_handle) = pb_info.get("UASharedPasteboardInfoDataFileKey") {
        if !graph.is_null(file_handle)? {
            graph.expect_class(file_handle, "NSFileHandle")?;
            bail!("file-handle-backed pasteboard data is unsupported");
        }
    }
    if let Some(path) = pb_info.get("UASharedPasteboardInfoDataPathKey") {
        if !graph.is_null(path)? && !graph.string(path)?.is_empty() {
            bail!("path-backed pasteboard data is unsupported");
        }
    }
    if let Some(extensions) = pb_info.get("UASharedPasteboardInfoExtensionKey") {
        if !graph.is_null(extensions)? {
            let (keys, values) = graph.dictionary(extensions)?;
            ensure!(
                keys.len() == values.len(),
                "sandbox-extension dictionary has mismatched key/value counts"
            );
            for (key, value) in keys.iter().zip(values) {
                graph.string(key)?;
                ensure!(
                    graph.class_is_subclass(value, "NSString")?
                        || graph.class_is_subclass(value, "NSData")?,
                    "sandbox-extension value has an unsupported class"
                );
                if graph.class_is_subclass(value, "NSString")? {
                    graph.string(value)?;
                } else {
                    graph.data(value)?;
                }
            }
        }
    }
    let items_ref = pb_info
        .get("UASharedPasteboardInfoItemsKey")
        .context("pasteboard info is missing items")?;
    let item_refs = graph.array(items_ref, &["NSArray", "NSMutableArray"])?;
    ensure!(
        item_refs.len() <= MAX_ITEMS,
        "pasteboard has too many items"
    );

    let mut representations = Vec::new();
    // Several representations can alias the same extraData range. Bound the
    // owned copies collectively, not just the serialized archive's size.
    let mut representation_bytes = 0usize;
    for item_ref in item_refs {
        let item = graph.object_dict(item_ref, "UASharedPasteboardItemInfo")?;
        let types_ref = item
            .get("UASharedPasteboardItemInfoTypesKey")
            .context("pasteboard item is missing types")?;
        let (type_keys, type_values) = graph.dictionary(types_ref)?;
        ensure!(
            type_keys.len() == type_values.len(),
            "pasteboard type dictionary has mismatched key/value counts"
        );
        for (type_key, type_value) in type_keys.iter().zip(type_values) {
            ensure!(
                representations.len() < MAX_REPRESENTATIONS,
                "pasteboard has too many representations"
            );
            let dictionary_uti = graph.string(type_key)?;
            let info = graph.object_dict(type_value, "UASharedPasteboardTypeInfo")?;
            let uti = graph.string(
                info.get("UASharedPasteboardTypeInfoTypeKey")
                    .context("type info is missing its UTI")?,
            )?;
            let provider_id = match info.get("UASharedPasteboardTypeInfoUUIDKey") {
                Some(uuid) if !graph.is_null(uuid)? => {
                    let object = graph.object_dict(uuid, "NSUUID")?;
                    object
                        .get("NS.uuidbytes")
                        .map(|value| {
                            let bytes = graph.data(value)?;
                            let id: [u8; 16] = bytes
                                .try_into()
                                .map_err(|_| anyhow::anyhow!("invalid provider UUID length"))?;
                            Ok::<_, anyhow::Error>(id)
                        })
                        .transpose()?
                }
                _ => None,
            };
            if let Some(file_handle) = info.get("UASharedPasteboardTypeInfoDataFileKey") {
                if !graph.is_null(file_handle)? {
                    graph.expect_class(file_handle, "NSFileHandle")?;
                    bail!("file-handle-backed pasteboard representation is unsupported");
                }
            }
            if let Some(index) = info.get("UASharedPasteboardTypeInfoIndex") {
                if !graph.is_null(index)? {
                    graph.integer(index)?;
                }
            }
            ensure!(
                uti == dictionary_uti,
                "pasteboard type key and type-info UTI disagree"
            );
            let offset = match info.get("UASharedPasteboardTypeInfoOffsetKey") {
                Some(value) if !graph.is_null(value)? => Some(graph.integer(value)?),
                _ => None,
            };
            let size = info
                .get("UASharedPasteboardTypeInfoSizeKey")
                .map(|value| graph.integer(value))
                .transpose()?;
            let data = match (&extra_data, offset, size) {
                (Some(extra), Some(offset), Some(size)) => {
                    let start =
                        usize::try_from(offset).context("pasteboard offset does not fit usize")?;
                    let length =
                        usize::try_from(size).context("pasteboard size does not fit usize")?;
                    let end = start
                        .checked_add(length)
                        .context("pasteboard offset plus size overflowed")?;
                    ensure!(
                        end <= extra.len(),
                        "pasteboard representation range {start}..{end} exceeds {} extraData bytes",
                        extra.len()
                    );
                    representation_bytes = representation_bytes
                        .checked_add(length)
                        .context("aggregate pasteboard representation size overflowed")?;
                    ensure!(
                        representation_bytes <= MAX_ARCHIVE_BYTES,
                        "aggregate pasteboard representation data exceeds {MAX_ARCHIVE_BYTES} byte cap"
                    );
                    Some(extra[start..end].to_vec())
                }
                (None, _, _) => None,
                (Some(_), _, _) => {
                    bail!("inline pasteboard data has incomplete offset/size metadata")
                }
            };
            representations.push(Representation {
                provider_id,
                uti,
                offset,
                size,
                data,
            });
        }
    }

    Ok(DecodedPasteboard {
        representations,
        extra_data_type,
        data_size,
        protocol_version: version,
    })
}

struct ArchiveGraph<'a> {
    objects: &'a [PlistValue],
}

impl ArchiveGraph<'_> {
    fn referenced<'a>(&'a self, value: &'a PlistValue) -> Result<&'a PlistValue> {
        let index = value
            .as_uid()
            .map(|uid| uid.get())
            .context("keyed archive object reference is not a UID")?;
        let index = usize::try_from(index).context("keyed archive UID does not fit usize")?;
        self.objects
            .get(index)
            .with_context(|| format!("keyed archive UID {index} is out of bounds"))
    }

    fn class_name<'a>(&'a self, value: &'a PlistValue) -> Result<&'a str> {
        let object = self.referenced(value)?;
        let object = object
            .as_dictionary()
            .context("expected keyed object dictionary")?;
        let class_ref = object
            .get("$class")
            .context("keyed object has no `$class`")?;
        let class = self.referenced(class_ref)?;
        class
            .as_dictionary()
            .and_then(|dict| dict.get("$classname"))
            .and_then(PlistValue::as_string)
            .context("keyed object has invalid class descriptor")
    }

    fn expect_class(&self, value: &PlistValue, expected: &str) -> Result<()> {
        ensure!(
            self.class_is_subclass(value, expected)?,
            "unsupported keyed archive class {:?}; expected {expected:?}",
            self.class_name(value)?
        );
        Ok(())
    }

    fn class_is_subclass(&self, value: &PlistValue, expected: &str) -> Result<bool> {
        let object = self.referenced(value)?;
        let object = object
            .as_dictionary()
            .context("expected keyed object dictionary")?;
        let class_ref = object
            .get("$class")
            .context("keyed object has no `$class`")?;
        let class = self
            .referenced(class_ref)?
            .as_dictionary()
            .context("keyed object has invalid class descriptor")?;
        let name = class
            .get("$classname")
            .and_then(PlistValue::as_string)
            .context("keyed object has invalid class name")?;
        let hierarchy = class
            .get("$classes")
            .and_then(PlistValue::as_array)
            .context("keyed object class descriptor has no `$classes`")?;
        Ok(name == expected || hierarchy.iter().any(|c| c.as_string() == Some(expected)))
    }

    fn object_dict<'a>(
        &'a self,
        value: &'a PlistValue,
        expected_class: &str,
    ) -> Result<&'a Dictionary> {
        self.expect_class(value, expected_class)?;
        self.referenced(value)?
            .as_dictionary()
            .context("keyed object is not a dictionary")
    }

    fn is_null(&self, value: &PlistValue) -> Result<bool> {
        if matches!(value, PlistValue::String(s) if s == "$null") {
            return Ok(true);
        }
        if let Some(uid) = value.as_uid() {
            if uid.get() == 0 {
                return Ok(true);
            }
            let referenced = self.referenced(value)?;
            return Ok(matches!(referenced, PlistValue::String(s) if s == "$null"));
        }
        Ok(false)
    }

    fn array<'a>(&'a self, value: &'a PlistValue, allowed: &[&str]) -> Result<&'a [PlistValue]> {
        let class_name = self.class_name(value)?;
        let mut accepted = false;
        for expected in allowed {
            if self.class_is_subclass(value, expected)? {
                accepted = true;
                break;
            }
        }
        ensure!(
            accepted,
            "unsupported keyed archive array class {class_name:?}"
        );
        let object = self
            .referenced(value)?
            .as_dictionary()
            .context("keyed array object is not a dictionary")?;
        object
            .get("NS.objects")
            .and_then(PlistValue::as_array)
            .map(Vec::as_slice)
            .context("keyed array has no `NS.objects` array")
    }

    fn dictionary<'a>(
        &'a self,
        value: &'a PlistValue,
    ) -> Result<(&'a [PlistValue], &'a [PlistValue])> {
        self.expect_class(value, "NSDictionary")?;
        let object = self
            .referenced(value)?
            .as_dictionary()
            .context("keyed dictionary object is not a dictionary")?;
        let keys = object
            .get("NS.keys")
            .and_then(PlistValue::as_array)
            .map(Vec::as_slice)
            .context("keyed dictionary has no `NS.keys` array")?;
        let values = object
            .get("NS.objects")
            .and_then(PlistValue::as_array)
            .map(Vec::as_slice)
            .context("keyed dictionary has no `NS.objects` array")?;
        Ok((keys, values))
    }

    fn string(&self, value: &PlistValue) -> Result<String> {
        if let Some(text) = value.as_string() {
            return Ok(text.to_string());
        }
        let resolved = self.referenced(value)?;
        if let Some(text) = resolved.as_string() {
            return Ok(text.to_string());
        }
        self.expect_class(value, "NSString")?;
        let object = resolved
            .as_dictionary()
            .context("keyed string object is not a dictionary")?;
        let text = object
            .get("NS.string")
            .context("keyed string has no `NS.string`")?;
        if let Some(text) = text.as_string() {
            return Ok(text.to_string());
        }
        self.referenced(text)?
            .as_string()
            .map(ToString::to_string)
            .context("keyed string `NS.string` is not a string")
    }

    fn integer(&self, value: &PlistValue) -> Result<u64> {
        if let Some(integer) = integer_value(value)? {
            return Ok(integer);
        }
        let resolved = self.referenced(value)?;
        if let Some(integer) = integer_value(resolved)? {
            return Ok(integer);
        }
        bail!("keyed integer is not an inline integer or UID to inline integer")
    }

    fn data(&self, value: &PlistValue) -> Result<Vec<u8>> {
        if let Some(data) = value.as_data() {
            return Ok(data.to_vec());
        }
        let resolved = self.referenced(value)?;
        if let Some(data) = resolved.as_data() {
            return Ok(data.to_vec());
        }
        self.expect_class(value, "NSData")?;
        let object = resolved
            .as_dictionary()
            .context("keyed data object is not a dictionary")?;
        let data = object
            .get("NS.data")
            .context("keyed data object has no `NS.data`")?;
        if let Some(data) = data.as_data() {
            return Ok(data.to_vec());
        }
        self.referenced(data)?
            .as_data()
            .map(ToOwned::to_owned)
            .context("keyed data `NS.data` is not data")
    }
}

fn integer_value(value: &PlistValue) -> Result<Option<u64>> {
    if let Some(integer) = value.as_unsigned_integer() {
        return Ok(Some(integer));
    }
    if let Some(integer) = value.as_signed_integer() {
        return u64::try_from(integer)
            .map(Some)
            .context("negative keyed archive integer");
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Uid;

    #[test]
    fn request_uses_observed_envelope_and_exact_caller_bytes() {
        let system_info = build_system_info_request(
            40,
            Value::dict([("name", Value::Str("test device".into()))]),
        )
        .unwrap();
        assert_eq!(system_info.get("_t").and_then(Value::as_u64), Some(2));
        assert_eq!(
            system_info.get("_i").and_then(Value::as_str),
            Some(SELECTOR_SYSTEM_INFO)
        );
        assert_eq!(system_info.get("_x").and_then(Value::as_u64), Some(40));

        let request =
            build_payload_request(41, COMMAND_PB_TYPES, "device-id", b"pbtypes!").unwrap();
        assert_eq!(request.get("_t").and_then(Value::as_u64), Some(2));
        assert_eq!(
            request.get("_i").and_then(Value::as_str),
            Some(SELECTOR_PAYLOAD_REQUEST)
        );
        assert_eq!(request.get("_x").and_then(Value::as_u64), Some(41));
        let content = request.get("_c").unwrap();
        assert_eq!(
            content.get("rClientCommand").and_then(Value::as_str),
            Some("pbtypes")
        );
        assert_eq!(
            content.get("rIdentifier").and_then(Value::as_str),
            Some("device-id")
        );
        assert_eq!(
            content.get("rAdvPayload").and_then(Value::as_bytes),
            Some(&b"pbtypes!"[..])
        );
    }

    #[test]
    fn response_requires_type_id_and_archive_field() {
        let response = Value::dict([
            ("_t", Value::Int(3)),
            ("_x", Value::Int(41)),
            (
                "_c",
                Value::dict([("rActPayload", Value::Bytes(vec![1, 2]))]),
            ),
        ]);
        assert_eq!(
            validate_payload_response(&response, 41).unwrap(),
            PayloadResponse::Archive(vec![1, 2])
        );
        assert!(validate_payload_response(&response, 42).is_err());
        let wrong_type = Value::dict([("_t", Value::Int(2)), ("_x", Value::Int(41))]);
        assert!(validate_payload_response(&wrong_type, 41).is_err());
        let remote_error = Value::dict([
            ("_t", Value::Int(3)),
            ("_x", Value::Int(41)),
            ("_em", Value::Str("unavailable".into())),
        ]);
        assert_eq!(
            validate_payload_response(&remote_error, 41).unwrap(),
            PayloadResponse::RemoteError("unavailable".into())
        );
    }

    #[test]
    fn parses_allowlisted_synthetic_keyed_archive_with_end_exclusive_ranges() {
        let archive = synthetic_archive("UASharedPasteboardInfoWrapper", 0, 4);
        let mut bytes = Vec::new();
        archive.to_writer_binary(&mut bytes).unwrap();
        let decoded = decode_pasteboard_archive(&bytes).unwrap();
        assert_eq!(decoded.protocol_version, Some(1));
        assert_eq!(decoded.extra_data_type, Some(0));
        assert_eq!(decoded.data_size, Some(4));
        assert_eq!(
            decoded.representations,
            vec![Representation {
                provider_id: None,
                uti: "public.utf8-plain-text".into(),
                offset: Some(0),
                size: Some(4),
                data: Some(b"text".to_vec()),
            }]
        );
    }

    #[test]
    fn provider_uuid_is_parsed_without_becoming_content_or_ordering() {
        use plist::Uid;
        let mut archive = synthetic_archive("UASharedPasteboardInfoWrapper", 0, 4);
        let objects = archive
            .as_dictionary_mut()
            .unwrap()
            .get_mut("$objects")
            .unwrap()
            .as_array_mut()
            .unwrap();
        let class_id = objects.len();
        let mut class = Dictionary::new();
        class.insert("$classname".into(), "NSUUID".into());
        class.insert(
            "$classes".into(),
            PlistValue::Array(vec!["NSUUID".into(), "NSObject".into()]),
        );
        objects.push(PlistValue::Dictionary(class));
        let uuid_id = objects.len();
        let mut uuid = Dictionary::new();
        uuid.insert("$class".into(), PlistValue::Uid(Uid::new(class_id as u64)));
        uuid.insert("NS.uuidbytes".into(), PlistValue::Data(vec![42; 16]));
        objects.push(PlistValue::Dictionary(uuid));
        let info = objects
            .iter_mut()
            .filter_map(PlistValue::as_dictionary_mut)
            .find(|d| d.contains_key("UASharedPasteboardTypeInfoTypeKey"))
            .unwrap();
        info.insert(
            "UASharedPasteboardTypeInfoUUIDKey".into(),
            PlistValue::Uid(Uid::new(uuid_id as u64)),
        );
        let mut bytes = Vec::new();
        archive.to_writer_binary(&mut bytes).unwrap();
        let board = decode_pasteboard_archive(&bytes).unwrap();
        assert_eq!(board.representations[0].provider_id, Some([42; 16]));
        assert_eq!(
            board.representations[0].data.as_deref(),
            Some(b"text".as_slice())
        );
    }

    #[test]
    fn metadata_can_have_null_offset_without_inline_data() {
        let mut archive = synthetic_archive("UASharedPasteboardInfoWrapper", 0, 4);
        let objects = archive
            .as_dictionary_mut()
            .unwrap()
            .get_mut("$objects")
            .unwrap()
            .as_array_mut()
            .unwrap();
        for object in objects {
            if let Some(dict) = object.as_dictionary_mut() {
                for key in [
                    "UASharedPasteboardTypeInfoOffsetKey",
                    "UASharedPasteboardInfoWrapperExtraDataKey",
                ] {
                    if dict.contains_key(key) {
                        dict.insert(key.into(), PlistValue::Uid(Uid::new(0)));
                    }
                }
            }
        }
        let mut bytes = Vec::new();
        archive.to_writer_binary(&mut bytes).unwrap();
        let board = decode_pasteboard_archive(&bytes).unwrap();
        assert_eq!(board.representations.len(), 1);
        assert_eq!(board.representations[0].offset, None);
        assert_eq!(board.representations[0].size, Some(4));
        assert_eq!(board.representations[0].data, None);
    }

    #[test]
    fn distinguishes_unavailable_pasteboard_from_malformed_archive() {
        let mut archive = synthetic_archive("UASharedPasteboardInfoWrapper", 0, 4);
        let dict = archive.as_dictionary_mut().unwrap();
        let root_index = dict["$top"].as_dictionary().unwrap()["root"]
            .as_uid()
            .unwrap()
            .get() as usize;
        let objects = dict.get_mut("$objects").unwrap().as_array_mut().unwrap();
        let wrapper = objects[root_index].as_dictionary_mut().unwrap();
        wrapper.insert(
            "UASharedPasteboardInfoWrapperPBInfoKey".into(),
            PlistValue::Uid(Uid::new(0)),
        );
        wrapper.insert(
            "UASharedPasteboardInfoWrapperExtraDataKey".into(),
            PlistValue::Uid(Uid::new(0)),
        );
        let mut bytes = Vec::new();
        archive.to_writer_binary(&mut bytes).unwrap();
        assert_eq!(
            decode_pasteboard_archive(&bytes).unwrap_err().to_string(),
            "clipboard archive contains no pasteboard info"
        );
    }

    #[test]
    fn decodes_macos15_foundation_archive_fixture() {
        // Encoded by Apple Foundation from source-defined historical UC model
        // classes. This validates archive compatibility, not a device capture.
        let decoded = decode_pasteboard_archive(include_bytes!(
            "../tests/fixtures/foundation-macos15-clipboard.bplist"
        ))
        .unwrap();
        assert_eq!(decoded.protocol_version, Some(1));
        assert_eq!(decoded.extra_data_type, Some(1));
        assert_eq!(decoded.data_size, Some(33));
        assert_eq!(
            decoded.representations,
            vec![Representation {
                provider_id: None,
                uti: "public.utf8-plain-text".into(),
                offset: Some(0),
                size: Some(33),
                data: Some(b"native-clipboard-fixture-20261015".to_vec()),
            }]
        );
    }

    #[test]
    fn rejects_unknown_root_class_and_out_of_bounds_representation() {
        let unknown = synthetic_archive("ExampleEvilClass", 0, 3);
        let mut bytes = Vec::new();
        unknown.to_writer_binary(&mut bytes).unwrap();
        assert!(decode_pasteboard_archive(&bytes)
            .unwrap_err()
            .to_string()
            .contains("unsupported keyed archive class"));

        let out_of_bounds = synthetic_archive("UASharedPasteboardInfoWrapper", 2, u64::MAX);
        let mut bytes = Vec::new();
        out_of_bounds.to_writer_binary(&mut bytes).unwrap();
        assert!(decode_pasteboard_archive(&bytes).is_err());
    }

    #[test]
    fn bounds_aggregate_clones_of_overlapping_inline_representations() {
        const PAYLOAD_BYTES: usize = 1024 * 1024;
        fn archive_with_aliases(copies: usize) -> Vec<u8> {
            let mut archive =
                synthetic_archive("UASharedPasteboardInfoWrapper", 0, PAYLOAD_BYTES as u64);
            let objects = archive
                .as_dictionary_mut()
                .unwrap()
                .get_mut("$objects")
                .unwrap()
                .as_array_mut()
                .unwrap();
            let items_index = objects
                .iter()
                .find_map(|object| {
                    object
                        .as_dictionary()?
                        .get("UASharedPasteboardInfoItemsKey")?
                        .as_uid()
                        .map(|uid| uid.get() as usize)
                })
                .unwrap();
            let items = objects[items_index]
                .as_dictionary_mut()
                .unwrap()
                .get_mut("NS.objects")
                .unwrap()
                .as_array_mut()
                .unwrap();
            // Repeated references to one item are legal graph aliases; each
            // decoded representation would otherwise allocate another payload.
            *items = vec![items[0].clone(); copies];
            for object in objects {
                if let PlistValue::Data(bytes) = object {
                    *bytes = vec![0x42; PAYLOAD_BYTES];
                } else if let Some(info) = object.as_dictionary_mut() {
                    if info.contains_key("UASharedPasteboardInfoDataSizeKey") {
                        info.insert(
                            "UASharedPasteboardInfoDataSizeKey".into(),
                            (PAYLOAD_BYTES as u64).into(),
                        );
                    }
                }
            }
            let mut bytes = Vec::new();
            archive.to_writer_binary(&mut bytes).unwrap();
            assert!(bytes.len() < MAX_ARCHIVE_BYTES);
            bytes
        }

        let accepted = archive_with_aliases(MAX_ARCHIVE_BYTES / PAYLOAD_BYTES);
        let decoded = decode_pasteboard_archive(&accepted).unwrap();
        assert_eq!(decoded.representations.len(), 8);
        assert_eq!(
            decoded
                .representations
                .iter()
                .map(|representation| representation.data.as_ref().unwrap().len())
                .sum::<usize>(),
            MAX_ARCHIVE_BYTES
        );
        let amplified = archive_with_aliases(MAX_ARCHIVE_BYTES / PAYLOAD_BYTES + 1);
        assert!(decode_pasteboard_archive(&amplified)
            .unwrap_err()
            .to_string()
            .contains("aggregate pasteboard representation data exceeds"));
    }

    fn synthetic_archive(root_class: &str, offset: u64, size: u64) -> PlistValue {
        let mut objects = vec![PlistValue::String("$null".into())];
        let mut add = |value: PlistValue| {
            let index = objects.len() as u64;
            objects.push(value);
            PlistValue::Uid(Uid::new(index))
        };
        let class = |name: &str| {
            let mut d = Dictionary::new();
            d.insert("$classname".into(), name.into());
            d.insert(
                "$classes".into(),
                vec![name.into(), "NSObject".into()].into(),
            );
            d
        };
        let wrapper_class = add(class(root_class).into());
        let info_class = add(class("UASharedPasteboardInfo").into());
        let item_class = add(class("UASharedPasteboardItemInfo").into());
        let type_class = add(class("UASharedPasteboardTypeInfo").into());
        let array_class = add(class("NSArray").into());
        let dict_class = add(class("NSDictionary").into());

        let uti = add(PlistValue::String("public.utf8-plain-text".into()));
        let offset_ref = add(offset.into());
        let size_ref = add(size.into());
        let type_info = add(keyed_object(
            type_class,
            [
                ("UASharedPasteboardTypeInfoTypeKey", uti.clone()),
                ("UASharedPasteboardTypeInfoOffsetKey", offset_ref),
                ("UASharedPasteboardTypeInfoSizeKey", size_ref),
            ],
        ));
        let types_dict = add(keyed_dictionary(
            dict_class,
            vec![uti.clone()],
            vec![type_info],
        ));
        let item = add(keyed_object(
            item_class,
            [("UASharedPasteboardItemInfoTypesKey", types_dict)],
        ));
        let items = add(keyed_array(array_class, vec![item]));
        let extra_data_ref = add(PlistValue::Data(b"text".to_vec()));
        let version_ref = add(1u64.into());
        let extra_data_type_ref = add(0u64.into());
        let data_size_ref = add(4u64.into());
        let pb_info = add(keyed_object(
            info_class,
            [
                ("UASharedPasteboardInfoItemsKey", items),
                ("UASharedPasteboardInfoDataSizeKey", data_size_ref),
            ],
        ));
        let wrapper = add(keyed_object(
            wrapper_class,
            [
                ("UASharedPasteboardInfoWrapperPBInfoKey", pb_info),
                ("UASharedPasteboardInfoWrapperExtraDataKey", extra_data_ref),
                (
                    "UASharedPasteboardInfoWrapperExtraTypeKey",
                    extra_data_type_ref,
                ),
                (
                    "UASharedPasteboardInfoWrapperProtocolVersionKey",
                    version_ref,
                ),
            ],
        ));
        let mut root = Dictionary::new();
        root.insert("$archiver".into(), "NSKeyedArchiver".into());
        root.insert("$version".into(), 100_000u64.into());
        root.insert("$objects".into(), PlistValue::Array(objects));
        let mut top = Dictionary::new();
        top.insert("root".into(), wrapper);
        root.insert("$top".into(), top.into());
        root.into()
    }

    fn keyed_object<const N: usize>(
        class: PlistValue,
        fields: [(&str, PlistValue); N],
    ) -> PlistValue {
        let mut d = Dictionary::new();
        for (key, value) in fields {
            d.insert(key.into(), value);
        }
        d.insert("$class".into(), class);
        d.into()
    }

    fn keyed_array(class: PlistValue, values: Vec<PlistValue>) -> PlistValue {
        let mut d = Dictionary::new();
        d.insert("NS.objects".into(), values.into());
        d.insert("$class".into(), class);
        d.into()
    }

    fn keyed_dictionary(
        class: PlistValue,
        keys: Vec<PlistValue>,
        values: Vec<PlistValue>,
    ) -> PlistValue {
        let mut d = Dictionary::new();
        d.insert("NS.keys".into(), keys.into());
        d.insert("NS.objects".into(), values.into());
        d.insert("$class".into(), class);
        d.into()
    }
}
