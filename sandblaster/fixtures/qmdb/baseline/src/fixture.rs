//! Host-side fixture loading with `run.ts`'s exact contract (not DSL code).
//!
//! The Bend 2 port's runner (`run.ts`) defines how a fixture is found,
//! validated and reported; `qmdb-cli`, the host tests and the benchmarks all
//! go through this module so they agree with it:
//!
//! * [`load_fixture`] — `loadFixture(source, index)`: `source` is inline JSON
//!   when it starts (after JavaScript `trimStart`) with `{` or `[`, otherwise
//!   a path to a regular file; both are limited to 1 MiB. The JSON is either
//!   one fixture, an array of fixtures, or `{"fixtures": [...]}`; `index`
//!   (a JavaScript `Number(..)` string) selects a row, and a single fixture
//!   only accepts index `"0"`.
//! * [`parse_fixture`] — `parseFixture(value)`: a JSON object with a
//!   non-empty `name` of at most 128 UTF-16 code units, lowercase-hex `root`,
//!   `key`, `value` (exactly 32 bytes each), `proof` (at most 4096 bytes) and
//!   a boolean `expected`. Error messages are `run.ts`'s, verbatim.
//! * One extension: an optional `chunk_bytes` field, the activity-chunk size
//!   N of the proof (`1` or `32`, see [`CHUNK_SIZES`]). Absent means N = 1,
//!   the `run.ts` contract (the Bend program and `qmdb/fixtures`);
//!   `qmdb/fixtures-n32` carries `"chunk_bytes": 32` (the production
//!   instance). Callers pick the verifier instance from it.
//! * [`Fixture::result_line`] — `JSON.stringify({name, verified, expected})`.
//!
//! JSON strings are kept as UTF-16 code units (like JavaScript), so names
//! with lone surrogates round-trip exactly. Known differences from Bun: the
//! text after `invalid JSON: ` (the engine's parser message) differs, and
//! nesting deeper than [`MAX_DEPTH`] is rejected as invalid JSON.

use std::fmt;
use std::path::Path;

/// Largest inline JSON argument or fixture file, in bytes (`MAX_JSON_BYTES`).
pub const MAX_JSON_BYTES: usize = 1 << 20;

/// Largest proof, in bytes (`MAX_PROOF_BYTES`).
pub const MAX_PROOF_BYTES: usize = 4096;

/// Deepest JSON nesting the parser accepts.
pub const MAX_DEPTH: usize = 512;

/// The activity-chunk sizes N a fixture may declare in `chunk_bytes`: the
/// Bend configuration (1, the default) and Commonware's production size (32).
pub const CHUNK_SIZES: [usize; 2] = [1, 32];

/// A validation or loading failure, carrying `run.ts`'s message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureError(pub String);

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FixtureError {}

fn fail<T>(message: impl Into<String>) -> Result<T, FixtureError> {
    Err(FixtureError(message.into()))
}

/// A validated fixture (`run.ts`'s `Fixture`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixture {
    /// The fixture name, as UTF-16 code units.
    pub name: Vec<u16>,
    /// Trusted canonical root, lowercase hex (32 bytes).
    pub root: String,
    /// Claimed key, lowercase hex (32 bytes).
    pub key: String,
    /// Claimed value, lowercase hex (32 bytes).
    pub value: String,
    /// Native proof bytes, lowercase hex (at most 4096 bytes).
    pub proof: String,
    /// Whether the proof should be accepted.
    pub expected: bool,
    /// Activity-chunk size N of the proof (`chunk_bytes`; 1 when absent).
    pub chunk_bytes: usize,
}

impl Fixture {
    /// The name as a Rust string (lone surrogates become U+FFFD).
    pub fn name_lossy(&self) -> String {
        String::from_utf16_lossy(&self.name)
    }

    /// The root, key, value and proof as bytes.
    pub fn bytes(&self) -> FixtureBytes {
        FixtureBytes {
            root: bytes_from_hex(&self.root).expect("validated hex"),
            key: bytes_from_hex(&self.key).expect("validated hex"),
            value: bytes_from_hex(&self.value).expect("validated hex"),
            proof: bytes_from_hex(&self.proof).expect("validated hex"),
        }
    }

    /// `run.ts`'s output line: `JSON.stringify({ name, verified, expected })`.
    pub fn result_line(&self, verified: bool) -> String {
        let mut out = String::from("{\"name\":");
        json_stringify_utf16(&self.name, &mut out);
        out.push_str(",\"verified\":");
        out.push_str(if verified { "true" } else { "false" });
        out.push_str(",\"expected\":");
        out.push_str(if self.expected { "true" } else { "false" });
        out.push('}');
        out
    }
}

/// Decoded fixture inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureBytes {
    pub root: Vec<u8>,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<u8>,
}

/// `bytesFromHex`: decode an even-length lowercase hex string.
pub fn bytes_from_hex(hex: &str) -> Result<Vec<u8>, FixtureError> {
    if !hex.len().is_multiple_of(2) || !is_lower_hex(hex) {
        return fail("hex input must contain an even number of lowercase hexadecimal digits");
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(hex.as_bytes().as_chunks::<2>().0.iter().map(|&[hi, lo]| digit(hi) << 4 | digit(lo)).collect())
}

/// Lowercase hex encoding.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 15)] as char);
    }
    out
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// JSON (RFC 8259, as accepted by JavaScript's `JSON.parse`)
// ---------------------------------------------------------------------------

/// A parsed JSON value. Strings are UTF-16 code units; numbers keep their
/// source text (the fixture contract never reads them).
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(Vec<u16>),
    Array(Vec<Json>),
    /// Members in source order; lookups take the last duplicate, like
    /// `JSON.parse`.
    Object(Vec<(Vec<u16>, Json)>),
}

impl Json {
    /// The member `key` of an object (last duplicate wins), if any.
    pub fn get(&self, key: &str) -> Option<&Json> {
        let Json::Object(members) = self else { return None };
        let key: Vec<u16> = key.encode_utf16().collect();
        members.iter().rev().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
}

/// Parse a JSON document (`JSON.parse`).
pub fn parse_json(text: &str) -> Result<Json, FixtureError> {
    let mut parser = Parser { s: text.as_bytes(), text, i: 0 };
    parser.ws();
    let value = parser.value(0)?;
    parser.ws();
    if parser.i != parser.s.len() {
        return parser.error("unexpected data after the JSON value");
    }
    Ok(value)
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn error<T>(&self, what: &str) -> Result<T, FixtureError> {
        fail(format!("invalid JSON: {what} at byte {}", self.i))
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.s.get(self.i) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, FixtureError> {
        if depth > MAX_DEPTH {
            return self.error("nesting too deep");
        }
        match self.s.get(self.i) {
            None => self.error("unexpected end of input"),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') if self.eat(b"true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Json::Bool(false)),
            Some(b'n') if self.eat(b"null") => Ok(Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.error("unexpected character"),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, FixtureError> {
        self.i += 1;
        let mut members = Vec::new();
        self.ws();
        if self.eat(b"}") {
            return Ok(Json::Object(members));
        }
        loop {
            self.ws();
            if self.s.get(self.i) != Some(&b'"') {
                return self.error("expected a property name");
            }
            let key = self.string()?;
            self.ws();
            if !self.eat(b":") {
                return self.error("expected ':'");
            }
            self.ws();
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.ws();
            if self.eat(b",") {
                continue;
            }
            if self.eat(b"}") {
                return Ok(Json::Object(members));
            }
            return self.error("expected ',' or '}'");
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, FixtureError> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.eat(b"]") {
            return Ok(Json::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            if self.eat(b",") {
                continue;
            }
            if self.eat(b"]") {
                return Ok(Json::Array(items));
            }
            return self.error("expected ',' or ']'");
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<Json, FixtureError> {
        let start = self.i;
        self.eat(b"-");
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return self.error("invalid number"),
        }
        if self.eat(b".") && self.digits() == 0 {
            return self.error("invalid number");
        }
        if let Some(b'e' | b'E') = self.s.get(self.i) {
            self.i += 1;
            if let Some(b'+' | b'-') = self.s.get(self.i) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return self.error("invalid number");
            }
        }
        Ok(Json::Number(self.text[start..self.i].to_string()))
    }

    fn hex4(&mut self) -> Result<u16, FixtureError> {
        let Some(digits) = self.s.get(self.i..self.i + 4) else {
            return self.error("invalid \\u escape");
        };
        let mut unit = 0u16;
        for &d in digits {
            let v = match d {
                b'0'..=b'9' => d - b'0',
                b'a'..=b'f' => d - b'a' + 10,
                b'A'..=b'F' => d - b'A' + 10,
                _ => return self.error("invalid \\u escape"),
            };
            unit = unit << 4 | u16::from(v);
        }
        self.i += 4;
        Ok(unit)
    }

    fn string(&mut self) -> Result<Vec<u16>, FixtureError> {
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let Some(&b) = self.s.get(self.i) else {
                return self.error("unterminated string");
            };
            match b {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let Some(&e) = self.s.get(self.i) else {
                        return self.error("unterminated string");
                    };
                    self.i += 1;
                    let unit = match e {
                        b'"' => 0x22,
                        b'\\' => 0x5c,
                        b'/' => 0x2f,
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => 0x0a,
                        b'r' => 0x0d,
                        b't' => 0x09,
                        b'u' => self.hex4()?,
                        _ => {
                            self.i -= 1;
                            return self.error("invalid escape");
                        }
                    };
                    out.push(unit);
                }
                0x00..=0x1f => return self.error("control character in string"),
                _ => {
                    // Copy one UTF-8 encoded scalar value as UTF-16.
                    let rest = &self.text[self.i..];
                    let c = rest.chars().next().expect("non-empty");
                    let mut buf = [0u16; 2];
                    out.extend_from_slice(c.encode_utf16(&mut buf));
                    self.i += c.len_utf8();
                }
            }
        }
    }
}

/// Append `JSON.stringify(s)` for a UTF-16 string (well-formed stringify:
/// lone surrogates are escaped).
pub fn json_stringify_utf16(s: &[u16], out: &mut String) {
    out.push('"');
    let mut units = s.iter().copied().peekable();
    while let Some(u) = units.next() {
        match u {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x00..=0x1f => out.push_str(&format!("\\u{u:04x}")),
            0xd800..=0xdbff => match units.peek() {
                Some(&low @ 0xdc00..=0xdfff) => {
                    units.next();
                    let c = 0x10000 + ((u32::from(u) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
                    out.push(char::from_u32(c).expect("valid surrogate pair"));
                }
                _ => out.push_str(&format!("\\u{u:04x}")),
            },
            0xdc00..=0xdfff => out.push_str(&format!("\\u{u:04x}")),
            _ => out.push(char::from_u32(u32::from(u)).expect("non-surrogate BMP unit")),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// run.ts
// ---------------------------------------------------------------------------

/// `checkedHex(value, field, bytes?)`.
fn checked_hex(value: Option<&Json>, field: &str, bytes: Option<usize>) -> Result<String, FixtureError> {
    let Some(Json::String(units)) = value else {
        return fail(format!("{field} must be a lowercase hexadecimal string"));
    };
    let ascii = units.iter().all(|&u| u < 0x80);
    let text: String = if ascii { units.iter().map(|&u| u as u8 as char).collect() } else { String::new() };
    if units.len() % 2 != 0 || !ascii || !is_lower_hex(&text) {
        return fail(format!("{field} must contain an even number of lowercase hexadecimal digits"));
    }
    if let Some(n) = bytes
        && units.len() != n * 2
    {
        return fail(format!("{field} must be exactly {n} bytes"));
    }
    Ok(text)
}

/// `parseFixture(value)`: validate one fixture object.
pub fn parse_fixture(value: &Json) -> Result<Fixture, FixtureError> {
    if !matches!(value, Json::Object(_)) {
        return fail("fixture must be a JSON object");
    }
    let name = match value.get("name") {
        Some(Json::String(name)) if !name.is_empty() && name.len() <= 128 => name.clone(),
        _ => return fail("name must be a non-empty string no longer than 128 characters"),
    };
    let root = checked_hex(value.get("root"), "root", Some(32))?;
    let key = checked_hex(value.get("key"), "key", Some(32))?;
    let claimed_value = checked_hex(value.get("value"), "value", Some(32))?;
    let proof = checked_hex(value.get("proof"), "proof", None)?;
    if proof.len() / 2 > MAX_PROOF_BYTES {
        return fail(format!("proof must be at most {MAX_PROOF_BYTES} bytes"));
    }
    let Some(&Json::Bool(expected)) = value.get("expected") else {
        return fail("expected must be a JSON boolean");
    };
    let chunk_bytes = match value.get("chunk_bytes") {
        None => 1,
        Some(Json::Number(text)) if text == "1" => 1,
        Some(Json::Number(text)) if text == "32" => 32,
        Some(_) => return fail("chunk_bytes must be 1 or 32"),
    };
    Ok(Fixture { name, root, key, value: claimed_value, proof, expected, chunk_bytes })
}

/// JavaScript's `String.prototype.trim` whitespace (WhiteSpace and
/// LineTerminator of ECMA-262).
fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// JavaScript's `Number(text)` for a string argument.
pub fn js_number(text: &str) -> f64 {
    let t = text.trim_matches(is_js_whitespace);
    if t.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(digits) = t.strip_prefix(prefix) {
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return f64::NAN;
            }
            return digits.chars().fold(0.0, |acc, c| acc * f64::from(radix) + f64::from(c.to_digit(radix).unwrap()));
        }
    }
    let (sign, body) = match t.as_bytes()[0] {
        b'+' => (1.0, &t[1..]),
        b'-' => (-1.0, &t[1..]),
        _ => (1.0, t),
    };
    if body == "Infinity" {
        return sign * f64::INFINITY;
    }
    // StrUnsignedDecimalLiteral: digits [. digits?] | . digits, then an
    // optional exponent. Rust's float parser accepts a superset ("inf",
    // "nan"), so validate the shape first.
    let b = body.as_bytes();
    let mut i = 0;
    let int_digits = b.iter().take_while(|c| c.is_ascii_digit()).count();
    i += int_digits;
    let mut frac_digits = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        frac_digits = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        i += frac_digits;
    }
    if int_digits == 0 && frac_digits == 0 {
        return f64::NAN;
    }
    if let Some(b'e' | b'E') = b.get(i) {
        i += 1;
        if let Some(b'+' | b'-') = b.get(i) {
            i += 1;
        }
        let exp_digits = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        if exp_digits == 0 {
            return f64::NAN;
        }
        i += exp_digits;
    }
    if i != b.len() {
        return f64::NAN;
    }
    sign * body.parse::<f64>().unwrap_or(f64::NAN)
}

/// `fixtureAt(value, rawIndex)`: select and validate one fixture.
pub fn fixture_at(value: &Json, raw_index: Option<&str>) -> Result<Fixture, FixtureError> {
    let rows = match value {
        Json::Array(rows) => Some(rows),
        Json::Object(_) => match value.get("fixtures") {
            Some(Json::Array(rows)) => Some(rows),
            _ => None,
        },
        _ => None,
    };
    let Some(rows) = rows else {
        if raw_index.is_some_and(|i| i != "0") {
            return fail("a single fixture only accepts index 0");
        }
        return parse_fixture(value);
    };
    let index = raw_index.map_or(0.0, js_number);
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    let safe = index.is_finite() && index.trunc() == index && index.abs() <= MAX_SAFE_INTEGER;
    if !safe || index < 0.0 || index >= rows.len() as f64 {
        return fail(format!(
            "fixture index must be an integer from 0 through {}",
            rows.len().saturating_sub(1)
        ));
    }
    parse_fixture(&rows[index as usize])
}

/// `loadFixture(source, index)`: load from inline JSON or a file path.
pub fn load_fixture(source: &str, index: Option<&str>) -> Result<Fixture, FixtureError> {
    let trimmed = source.trim_start_matches(is_js_whitespace);
    let text = if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if source.len() > MAX_JSON_BYTES {
            return fail(format!("inline JSON must be at most {MAX_JSON_BYTES} bytes"));
        }
        source.to_string()
    } else {
        let file = std::path::absolute(Path::new(source)).unwrap_or_else(|_| Path::new(source).to_path_buf());
        let meta = match std::fs::metadata(&file) {
            Ok(meta) => meta,
            Err(error) => return fail(io_message(&error, &file)),
        };
        if !meta.is_file() {
            return fail(format!("{source} is not a regular file"));
        }
        if meta.len() > MAX_JSON_BYTES as u64 {
            return fail(format!("fixture file must be at most {MAX_JSON_BYTES} bytes"));
        }
        match std::fs::read(&file) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) => return fail(io_message(&error, &file)),
        }
    };
    let parsed = parse_json(&text)?;
    fixture_at(&parsed, index)
}

/// Node-style error text for a failed `stat`/`read` (`ENOENT: no such file
/// or directory, stat '/abs/path'`).
fn io_message(error: &std::io::Error, file: &Path) -> String {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => "ENOENT: no such file or directory",
        std::io::ErrorKind::PermissionDenied => "EACCES: permission denied",
        _ => return format!("{error}, stat '{}'", file.display()),
    };
    format!("{code}, stat '{}'", file.display())
}

/// Every per-question fixture in `dir`, sorted by file name (as `tests.ts`
/// enumerates them): the `*.json` files whose name starts with a digit
/// (`NNN-accept-….json`, `NNN-reject-….json`). The aggregate exports next to
/// them (`verdicts.json`, `known-answers.json`, `databases.json`) are skipped.
pub fn fixture_files(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut files: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| is_fixture_file(path))
        .collect();
    files.sort();
    Ok(files)
}

/// Whether `path` names a per-question fixture: a `*.json` file whose name
/// starts with an ASCII digit.
pub fn is_fixture_file(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "json")
        && path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(|c: char| c.is_ascii_digit()))
}

/// The committed fixture corpus (`qmdb/fixtures`): N = 1, the `run.ts`
/// regression set of the Bend program.
pub fn corpus_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

/// The committed N = 32 corpus (`qmdb/fixtures-n32`, exported from
/// `qmdb/oracle` with Commonware's verdicts; every file has
/// `"chunk_bytes": 32`).
pub fn corpus_dir_n32() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures-n32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trips_strings() {
        let v = parse_json(r#"{"a":"x\u00e9\ud83d\ude00\"\\\n","a":"last","n":-1.5e3,"z":[true,false,null]}"#)
            .unwrap();
        let Json::String(s) = v.get("a").unwrap() else { panic!() };
        assert_eq!(String::from_utf16(s).unwrap(), "last");
        let mut out = String::new();
        json_stringify_utf16(&"x\u{e9}\u{1f600}\"\\\n\u{1}".encode_utf16().collect::<Vec<_>>(), &mut out);
        assert_eq!(out, "\"x\u{e9}\u{1f600}\\\"\\\\\\n\\u0001\"");
        let mut lone = String::new();
        json_stringify_utf16(&[0xd800, 0x41], &mut lone);
        assert_eq!(lone, "\"\\ud800A\"");
        for bad in ["", "{", "[1,]", "{\"a\" 1}", "01", "1.", "\"\u{1}\"", "tru", "{} x", "\"\\x\""] {
            assert!(parse_json(bad).is_err(), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn js_number_matches_javascript() {
        assert_eq!(js_number(""), 0.0);
        assert_eq!(js_number(" 12 "), 12.0);
        assert_eq!(js_number("0x1f"), 31.0);
        assert_eq!(js_number("1e1"), 10.0);
        assert_eq!(js_number(".5"), 0.5);
        assert_eq!(js_number("-0"), 0.0);
        assert!(js_number("1a").is_nan());
        assert!(js_number("inf").is_nan());
        assert!(js_number("-0x1").is_nan());
        assert_eq!(js_number("Infinity"), f64::INFINITY);
    }

    #[test]
    fn validation_messages() {
        let good = r#"{"name":"n","root":"00000000000000000000000000000000000000000000000000000000000000aa","key":"0000000000000000000000000000000000000000000000000000000000000000","value":"0000000000000000000000000000000000000000000000000000000000000000","proof":"00","expected":false}"#;
        let fixture = load_fixture(good, None).unwrap();
        assert_eq!(fixture.result_line(true), r#"{"name":"n","verified":true,"expected":false}"#);
        assert_eq!(load_fixture(good, Some("1")).unwrap_err().0, "a single fixture only accepts index 0");
        let list = format!("[{good},{good}]");
        assert!(load_fixture(&list, Some("1")).is_ok());
        assert_eq!(
            load_fixture(&list, Some("2")).unwrap_err().0,
            "fixture index must be an integer from 0 through 1"
        );
        assert_eq!(
            load_fixture("[]", None).unwrap_err().0,
            "fixture index must be an integer from 0 through 0"
        );
        let upper = good.replace("aa\"", "AA\"");
        assert_eq!(
            load_fixture(&upper, None).unwrap_err().0,
            "root must contain an even number of lowercase hexadecimal digits"
        );
        let expected01 = good.replace("\"expected\":false", "\"expected\":\"01\"");
        assert_eq!(load_fixture(&expected01, None).unwrap_err().0, "expected must be a JSON boolean");
        let big = good.replace("\"proof\":\"00\"", &format!("\"proof\":\"{}\"", "00".repeat(4097)));
        assert_eq!(load_fixture(&big, None).unwrap_err().0, "proof must be at most 4096 bytes");
        let short = good.replace("aa\"", "\"");
        assert_eq!(load_fixture(&short, None).unwrap_err().0, "root must be exactly 32 bytes");
        assert!(load_fixture("5", None).unwrap_err().0.starts_with("ENOENT"));
        assert!(load_fixture("{", None).unwrap_err().0.starts_with("invalid JSON: "));
        assert_eq!(load_fixture("[5]", None).unwrap_err().0, "fixture must be a JSON object");
    }

    #[test]
    fn chunk_bytes_defaults_to_one() {
        let good = r#"{"name":"n","root":"00000000000000000000000000000000000000000000000000000000000000aa","key":"0000000000000000000000000000000000000000000000000000000000000000","value":"0000000000000000000000000000000000000000000000000000000000000000","proof":"00","expected":false}"#;
        assert_eq!(load_fixture(good, None).unwrap().chunk_bytes, 1);
        let with = |field: &str| good.replace("\"expected\"", &format!("\"chunk_bytes\":{field},\"expected\""));
        assert_eq!(load_fixture(&with("32"), None).unwrap().chunk_bytes, 32);
        assert_eq!(load_fixture(&with("1"), None).unwrap().chunk_bytes, 1);
        for bad in ["2", "32.0", "\"32\"", "null", "-1"] {
            assert_eq!(load_fixture(&with(bad), None).unwrap_err().0, "chunk_bytes must be 1 or 32", "{bad}");
        }
    }
}
