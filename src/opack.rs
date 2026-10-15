//! OPACK encoding for Companion messages. Integer and data lengths are little endian.
//! Protocol cross-check: pyatv/support/opack.py (2026-09-16); no runtime dependency.
//! The decoder bounds nesting, object count, references, and total input.

#![allow(dead_code)] // M2/M3 scaffolding: exercised by unit tests; wired into the runtime once macOS keys exist.

use anyhow::{bail, ensure, Context, Result};

/// An OPACK value. Dicts keep insertion order and allow non-string keys, so we
/// model them as an ordered list of pairs rather than a map.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Float(f64),
    Uuid([u8; 16]),
    Time(u64),
    Bool(bool),
    Int(u64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Dict(Vec<(Value, Value)>),
}

impl Value {
    /// Convenience: build a dict from string keys.
    pub fn dict<I: IntoIterator<Item = (&'static str, Value)>>(pairs: I) -> Value {
        Value::Dict(
            pairs
                .into_iter()
                .map(|(k, v)| (Value::Str(k.to_string()), v))
                .collect(),
        )
    }

    /// Look up a string key in a dict.
    pub fn get(&self, key: &str) -> Option<&Value> {
        if let Value::Dict(pairs) = self {
            pairs
                .iter()
                .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
                .map(|(_, v)| v)
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(v) => Some(*v),
            _ => None,
        }
    }
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.push(4),
        Value::Float(v) => {
            out.push(0x36);
            out.extend(v.to_le_bytes());
        }
        Value::Uuid(v) => {
            out.push(5);
            out.extend(v);
        }
        Value::Time(v) => {
            out.push(6);
            out.extend(v.to_le_bytes());
        }
        Value::Bool(true) => out.push(0x01),
        Value::Bool(false) => out.push(0x02),
        Value::Int(v) => encode_int(*v, out),
        Value::Str(s) => encode_str(s, out),
        Value::Bytes(b) => encode_bytes(b, out),
        Value::Array(items) => {
            if items.len() < 0x0F {
                out.push(0xD0 + items.len() as u8);
                for it in items {
                    encode_into(it, out);
                }
            } else {
                out.push(0xDF);
                for it in items {
                    encode_into(it, out);
                }
                out.push(0x03);
            }
        }
        Value::Dict(pairs) => {
            if pairs.len() < 0x0F {
                out.push(0xE0 + pairs.len() as u8);
                for (k, v) in pairs {
                    encode_into(k, out);
                    encode_into(v, out);
                }
            } else {
                out.push(0xEF);
                for (k, v) in pairs {
                    encode_into(k, out);
                    encode_into(v, out);
                }
                out.push(0x03);
            }
        }
    }
}

fn encode_int(value: u64, out: &mut Vec<u8>) {
    if value < 0x28 {
        out.push(value as u8 + 8);
        return;
    }
    let (tag, size) = if value <= 0xff {
        (0x30, 1)
    } else if value <= 0xffff {
        (0x31, 2)
    } else if value <= 0xffff_ffff {
        (0x32, 4)
    } else {
        (0x33, 8)
    };
    out.push(tag);
    out.extend(&value.to_le_bytes()[..size]);
}
fn encode_str(s: &str, out: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    let n = bytes.len();
    if n <= 32 {
        out.push(0x40 + n as u8);
    } else {
        let width = if n <= 255 {
            1
        } else if n <= 65535 {
            2
        } else if n <= 0xffffff {
            3
        } else {
            4
        };
        out.push(0x60 + width as u8);
        out.extend(&(n as u64).to_le_bytes()[..width]);
    }
    out.extend(bytes);
}
fn encode_bytes(b: &[u8], out: &mut Vec<u8>) {
    let n = b.len();
    if n <= 32 {
        out.push(0x70 + n as u8);
    } else {
        let (tag, width) = if n <= 255 {
            (0x91, 1)
        } else if n <= 65535 {
            (0x92, 2)
        } else if n <= 0xffff_ffff {
            (0x93, 4)
        } else {
            (0x94, 8)
        };
        out.push(tag);
        out.extend(&(n as u64).to_le_bytes()[..width]);
    }
    out.extend(b);
}

pub fn decode(data: &[u8]) -> Result<Value> {
    ensure!(data.len() <= 4 * 1024 * 1024, "OPACK input exceeds 4 MiB");
    let mut d = Decoder {
        data,
        pos: 0,
        objects: Vec::new(),
        count: 0,
        budget: 16 * 1024 * 1024,
    };
    let value = d.parse(0)?;
    ensure!(d.pos == data.len(), "OPACK trailing bytes");
    Ok(value)
}
struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    objects: Vec<Value>,
    count: usize,
    budget: usize,
}
impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        ensure!(n <= self.data.len() - self.pos, "OPACK unexpected end");
        let start = self.pos;
        self.pos += n;
        Ok(&self.data[start..self.pos])
    }
    fn number(&mut self, n: usize) -> Result<u64> {
        let mut b = [0; 8];
        b[..n].copy_from_slice(self.take(n)?);
        Ok(u64::from_le_bytes(b))
    }
    fn charge(&mut self, n: usize) -> Result<()> {
        self.budget = self
            .budget
            .checked_sub(n)
            .context("OPACK allocation limit")?;
        Ok(())
    }
    fn parse(&mut self, depth: usize) -> Result<Value> {
        self.count += 1;
        ensure!(
            depth <= 64 && self.count <= 65536,
            "OPACK nesting/object limit"
        );
        self.charge(32)?;
        let t = self.take(1)?[0];
        let mut remember = true;
        let value = match t {
            1 => {
                remember = false;
                Value::Bool(true)
            }
            2 => {
                remember = false;
                Value::Bool(false)
            }
            4 => {
                remember = false;
                Value::Null
            }
            5 => Value::Uuid(self.take(16)?.try_into()?),
            6 => Value::Time(self.number(8)?),
            8..=0x2f => {
                remember = false;
                Value::Int((t - 8) as u64)
            }
            0x30..=0x33 => Value::Int(self.number(1 << (t - 0x30))?),
            0x35 => Value::Float(f32::from_bits(self.number(4)? as u32) as f64),
            0x36 => Value::Float(f64::from_bits(self.number(8)?)),
            0x40..=0x64 => {
                let n = if t <= 0x60 {
                    (t - 0x40) as usize
                } else {
                    usize::try_from(self.number((t - 0x60) as usize)?)?
                };
                self.charge(n * 2)?;
                Value::Str(std::str::from_utf8(self.take(n)?)?.to_string())
            }
            0x70..=0x94 => {
                let n = if t <= 0x90 {
                    (t - 0x70) as usize
                } else {
                    usize::try_from(self.number(1 << (t - 0x91))?)?
                };
                ensure!(n <= 4 * 1024 * 1024, "OPACK data limit");
                self.charge(n * 2)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            0xa0..=0xc4 => {
                remember = false;
                let index = if t <= 0xc0 {
                    (t - 0xa0) as usize
                } else {
                    usize::try_from(self.number((t - 0xc0) as usize)?)?
                };
                let object = self
                    .objects
                    .get(index)
                    .context("OPACK invalid object reference")?;
                let size = match object {
                    Value::Str(s) => s.len(),
                    Value::Bytes(b) => b.len(),
                    _ => 16,
                };
                self.charge(size)?;
                self.objects[index].clone()
            }
            0xd0..=0xdf => {
                remember = false;
                let mut items = Vec::new();
                let n = (t & 15) as usize;
                loop {
                    if n < 15 && items.len() == n {
                        break;
                    }
                    if n == 15 && self.data.get(self.pos) == Some(&3) {
                        self.pos += 1;
                        break;
                    }
                    items.push(self.parse(depth + 1)?);
                }
                Value::Array(items)
            }
            0xe0..=0xef => {
                remember = false;
                let mut items = Vec::new();
                let n = (t & 15) as usize;
                loop {
                    if n < 15 && items.len() == n {
                        break;
                    }
                    if n == 15 && self.data.get(self.pos) == Some(&3) {
                        self.pos += 1;
                        break;
                    }
                    items.push((self.parse(depth + 1)?, self.parse(depth + 1)?));
                }
                Value::Dict(items)
            }
            _ => bail!("OPACK unsupported tag {t:#x}"),
        };
        // Native CoreUtils indexes every eligible literal occurrence, including
        // duplicates. Empty strings/data and small integers are never indexed,
        // even when encoded using a longer length/integer tag.
        remember &= match &value {
            Value::Str(s) => !s.is_empty(),
            Value::Bytes(b) => !b.is_empty(),
            Value::Int(n) => *n >= 40,
            _ => true,
        };
        if remember {
            self.objects.push(value.clone());
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: Value) {
        let enc = encode(&v);
        let dec = decode(&enc).expect("decode");
        assert_eq!(
            v,
            dec,
            "roundtrip mismatch; encoded = {}",
            hex::encode(&enc)
        );
    }

    #[test]
    fn companion_integer_wire_vector() {
        // Independent protocol fixture: 32-bit little-endian integer.
        let v = Value::dict([("pf", Value::Int(266256))]);
        let enc = encode(&v);
        // E1 (dict,1) | 42 'p'(70) 'f'(66) (str len2) | 32 (int,3 bytes) 04 10 10
        // (266256 == 0x041010)
        assert_eq!(hex::encode(&enc), "e14270663210100400");
        assert_eq!(decode(&enc).unwrap(), v);
    }

    #[test]
    fn ints() {
        for v in [
            0u64,
            1,
            0x26,
            0x27,
            0xFF,
            0x100,
            266256,
            0x00FF_FFFF,
            0x0100_0000,
            u32::MAX as u64,
        ] {
            roundtrip(Value::Int(v));
        }
        // small-int encoding boundary
        assert_eq!(encode(&Value::Int(0)), vec![0x08]);
        assert_eq!(encode(&Value::Int(0x26)), vec![0x2E]);
        assert_eq!(encode(&Value::Int(0x27)), vec![0x2f]);
    }

    #[test]
    fn strings_short_and_long() {
        roundtrip(Value::Str("_pd".into()));
        roundtrip(Value::Str("x".repeat(0x20)));
        roundtrip(Value::Str("y".repeat(0x21))); // triggers long form
        roundtrip(Value::Str("z".repeat(500)));
    }

    #[test]
    fn bytes_and_containers() {
        roundtrip(Value::Bytes(vec![0u8; 10]));
        roundtrip(Value::Bytes(vec![0xABu8; 300])); // long form
        roundtrip(Value::Array((0..20).map(Value::Int).collect())); // endless form
        roundtrip(Value::Array(vec![
            Value::Bool(true),
            Value::Str("a".into()),
        ]));
        let big: Vec<(Value, Value)> = (0..20)
            .map(|i| (Value::Str(format!("k{i}")), Value::Int(i)))
            .collect();
        roundtrip(Value::Dict(big)); // endless dict
    }

    #[test]
    fn nested() {
        let v = Value::dict([
            ("_pd", Value::Bytes(vec![1, 2, 3])),
            (
                "list",
                Value::Array(vec![
                    Value::Int(1),
                    Value::dict([("a", Value::Bool(false))]),
                ]),
            ),
        ]);
        roundtrip(v);
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    #[test]
    fn scalar_references_and_bounds() {
        assert_eq!(
            decode(&hex::decode("d24568656c6c6fa0").unwrap()).unwrap(),
            Value::Array(vec![Value::Str("hello".into()); 2])
        );
        assert_eq!(
            encode(&Value::Int(0x12345678)),
            hex::decode("3278563412").unwrap()
        );
        assert_eq!(
            encode(&Value::Int(u64::MAX)),
            [vec![0x33], vec![0xff; 8]].concat()
        );
        assert!(decode(&[0xa0]).is_err());
        assert!(decode(&[1, 2]).is_err());
        assert!(decode(&[vec![0xd1; 66], vec![1]].concat()).is_err());
        assert!(decode(&[0x94, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    }
    // Synthetic vectors verified with macOS CoreUtils OPACKEncoderCreateData
    // and OPACKDecodeBytes (flags=0). No captured device or clipboard values.
    #[test]
    fn native_empty_literals_do_not_shift_references() {
        for wire in ["d3404161a0", "d361004161a0"] {
            assert_eq!(
                decode(&hex::decode(wire).unwrap()).unwrap(),
                Value::Array(vec![
                    Value::Str("".into()),
                    Value::Str("a".into()),
                    Value::Str("a".into())
                ])
            );
        }
        for wire in ["d3704161a0", "d391004161a0"] {
            assert_eq!(
                decode(&hex::decode(wire).unwrap()).unwrap(),
                Value::Array(vec![
                    Value::Bytes(vec![]),
                    Value::Str("a".into()),
                    Value::Str("a".into())
                ])
            );
        }
        for wire in ["d361004161a1", "d391004161a1"] {
            assert!(decode(&hex::decode(wire).unwrap()).is_err());
        }
    }

    #[test]
    fn native_literal_occurrences_are_not_deduplicated() {
        for (wire, last) in [("d4416141614162a2", "b"), ("d4416141614162a1", "a")] {
            assert_eq!(
                decode(&hex::decode(wire).unwrap()).unwrap(),
                Value::Array(vec![
                    Value::Str("a".into()),
                    Value::Str("a".into()),
                    Value::Str("b".into()),
                    Value::Str(last.into())
                ])
            );
        }
        assert_eq!(
            decode(&hex::decode("d430283128004161a2").unwrap()).unwrap(),
            Value::Array(vec![
                Value::Int(40),
                Value::Int(40),
                Value::Str("a".into()),
                Value::Str("a".into())
            ])
        );
    }

    #[test]
    fn native_small_integer_eligibility_is_independent_of_width() {
        for wire in ["d330014161a1", "d330274161a1"] {
            assert!(decode(&hex::decode(wire).unwrap()).is_err());
        }
        for (wire, number) in [("d330274161a0", 39), ("d330284161a1", 40)] {
            assert_eq!(
                decode(&hex::decode(wire).unwrap()).unwrap(),
                Value::Array(vec![
                    Value::Int(number),
                    Value::Str("a".into()),
                    Value::Str("a".into())
                ])
            );
        }
        assert_eq!(
            decode(&hex::decode("d4350000803f094161a1").unwrap()).unwrap(),
            Value::Array(vec![
                Value::Float(1.0),
                Value::Int(1),
                Value::Str("a".into()),
                Value::Str("a".into())
            ])
        );
    }

    #[test]
    fn native_system_info_selector_reference_survives_nested_empty_value() {
        let wire = "e3425f63e245656d70747940425f69466e6573746564a24b5f73797374656d496e666f425f740a";
        let value = decode(&hex::decode(wire).unwrap()).unwrap();
        assert_eq!(value.get("_i"), Some(&Value::Str("_systemInfo".into())));
        assert_eq!(value.get("_t"), Some(&Value::Int(2)));
        assert_eq!(
            value.get("_c").unwrap().get("empty"),
            Some(&Value::Str("".into()))
        );
    }
}
