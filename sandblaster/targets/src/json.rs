//! A minimal JSON reader and writer for the evidence records.
//!
//! The evidence records `evidence/<arch>.json` (DESIGN.md §9.2 "Validation")
//! are part of the trusted target-semantics library's paper trail, and the
//! dispatcher consults them fail-closed. To keep the crate free of third-party
//! code the records are written and read by this small module: a recursive
//! descent parser over RFC 8259 JSON (numbers are kept as their source text,
//! objects keep their key order) and a deterministic pretty printer.
#![forbid(unsafe_code)]

use std::fmt::Write as _;

/// A JSON value. Object members keep their order; numbers keep their text.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number, as written (validated by the parser).
    Num(String),
    /// A string (unescaped).
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object, members in source order.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// A string value.
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    /// An unsigned integer value.
    pub fn uint(n: u64) -> Json {
        Json::Num(n.to_string())
    }

    /// An object from `(key, value)` pairs.
    pub fn obj<const N: usize>(members: [(&str, Json); N]) -> Json {
        Json::Obj(
            members
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    /// Member `key` of an object (first occurrence).
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The value as `u64`, if this is a non-negative integer that fits.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    /// The boolean, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(xs) => Some(xs),
            _ => None,
        }
    }

    /// Pretty-print with two-space indentation and a trailing newline.
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out.push('\n');
        out
    }

    fn write_pretty(&self, out: &mut String, indent: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(n),
            Json::Str(s) => write_string(out, s),
            Json::Arr(xs) if xs.is_empty() => out.push_str("[]"),
            Json::Arr(xs) => {
                // Arrays of scalars stay on one line; others get one element per line.
                if xs.iter().all(|x| !matches!(x, Json::Arr(_) | Json::Obj(_))) {
                    out.push('[');
                    for (i, x) in xs.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        x.write_pretty(out, indent);
                    }
                    out.push(']');
                } else {
                    out.push_str("[\n");
                    for (i, x) in xs.iter().enumerate() {
                        push_indent(out, indent + 1);
                        x.write_pretty(out, indent + 1);
                        out.push_str(if i + 1 < xs.len() { ",\n" } else { "\n" });
                    }
                    push_indent(out, indent);
                    out.push(']');
                }
            }
            Json::Obj(members) if members.is_empty() => out.push_str("{}"),
            Json::Obj(members) => {
                out.push_str("{\n");
                for (i, (k, v)) in members.iter().enumerate() {
                    push_indent(out, indent + 1);
                    write_string(out, k);
                    out.push_str(": ");
                    v.write_pretty(out, indent + 1);
                    out.push_str(if i + 1 < members.len() { ",\n" } else { "\n" });
                }
                push_indent(out, indent);
                out.push('}');
            }
        }
    }
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A parse error with the byte offset where it was detected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset into the input.
    pub offset: usize,
    /// What went wrong.
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "JSON parse error at byte {}: {}",
            self.offset, self.message
        )
    }
}

impl std::error::Error for ParseError {}

/// Parse a complete JSON document.
pub fn parse(text: &str) -> Result<Json, ParseError> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(p.err("trailing characters after the document"));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

/// Nesting limit (evidence records are three levels deep).
const MAX_DEPTH: usize = 64;

impl Parser<'_> {
    fn err(&self, message: &str) -> ParseError {
        ParseError {
            offset: self.i,
            message: message.to_string(),
        }
    }

    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.s[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        match self.s.get(self.i) {
            None => Err(self.err("unexpected end of input")),
            Some(b'n') if self.eat("null") => Ok(Json::Null),
            Some(b't') if self.eat("true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat("false") => Ok(Json::Bool(false)),
            Some(b'"') => self.string().map(Json::Str),
            Some(b'[') => {
                self.i += 1;
                let mut xs = Vec::new();
                self.ws();
                if self.eat("]") {
                    return Ok(Json::Arr(xs));
                }
                loop {
                    self.ws();
                    xs.push(self.value(depth + 1)?);
                    self.ws();
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat("]") {
                        return Ok(Json::Arr(xs));
                    }
                    return Err(self.err("expected ',' or ']'"));
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut members = Vec::new();
                self.ws();
                if self.eat("}") {
                    return Ok(Json::Obj(members));
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return Err(self.err("expected a string key"));
                    }
                    let k = self.string()?;
                    self.ws();
                    if !self.eat(":") {
                        return Err(self.err("expected ':'"));
                    }
                    self.ws();
                    let v = self.value(depth + 1)?;
                    members.push((k, v));
                    self.ws();
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat("}") {
                        return Ok(Json::Obj(members));
                    }
                    return Err(self.err("expected ',' or '}'"));
                }
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let d0 = p.i;
            while p.i < p.s.len() && p.s[p.i].is_ascii_digit() {
                p.i += 1;
            }
            p.i > d0
        };
        self.eat("-");
        if self.eat("0") {
            // A leading zero may not be followed by more digits.
        } else if !digits(self) {
            return Err(self.err("expected digits"));
        }
        if self.eat(".") && !digits(self) {
            return Err(self.err("expected fraction digits"));
        }
        if self.eat("e") || self.eat("E") {
            let _ = self.eat("+") || self.eat("-");
            if !digits(self) {
                return Err(self.err("expected exponent digits"));
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).expect("ASCII number");
        Ok(Json::Num(text.to_string()))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self
            .s
            .get(self.i..self.i + 4)
            .ok_or_else(|| self.err("short \\u escape"))?;
        let h = std::str::from_utf8(h).map_err(|_| self.err("bad \\u escape"))?;
        let v = u32::from_str_radix(h, 16).map_err(|_| self.err("bad \\u escape"))?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        debug_assert_eq!(self.s[self.i], b'"');
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.i < self.s.len() && !matches!(self.s[self.i], b'"' | b'\\') {
                if self.s[self.i] < 0x20 {
                    return Err(self.err("control character in string"));
                }
                self.i += 1;
            }
            out.push_str(
                std::str::from_utf8(&self.s[start..self.i])
                    .map_err(|_| self.err("invalid UTF-8"))?,
            );
            match self.s.get(self.i) {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(_) => {
                    self.i += 1;
                    let c = *self
                        .s
                        .get(self.i)
                        .ok_or_else(|| self.err("unterminated escape"))?;
                    self.i += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                if !self.eat("\\u") {
                                    return Err(self.err("unpaired surrogate"));
                                }
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return Err(self.err("unpaired surrogate"));
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else {
                                hi
                            };
                            out.push(
                                char::from_u32(cp).ok_or_else(|| self.err("invalid code point"))?,
                            );
                        }
                        _ => return Err(self.err("unknown escape")),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let v = Json::obj([
            ("a", Json::uint(10_000_000)),
            ("b", Json::str("x\"y\\z\n\u{1}é")),
            (
                "c",
                Json::Arr(vec![
                    Json::Null,
                    Json::Bool(true),
                    Json::Num("-1.5e3".into()),
                ]),
            ),
            ("d", Json::Arr(vec![Json::obj([("k", Json::Arr(vec![]))])])),
            ("e", Json::Obj(vec![])),
        ]);
        let text = v.to_pretty();
        assert_eq!(parse(&text).unwrap(), v);
        assert_eq!(v.get("a").and_then(Json::as_u64), Some(10_000_000));
        assert_eq!(v.get("b").and_then(Json::as_str), Some("x\"y\\z\n\u{1}é"));
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\" 1}",
            "01",
            "1.",
            "\"\\x\"",
            "[1] 2",
            "\"\\ud800\"",
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(
            parse(" [ 1 , {\"k\" : \"\\u00e9\\ud83d\\ude00\"} ] ").unwrap(),
            Json::Arr(vec![Json::uint(1), Json::obj([("k", Json::str("é😀"))])])
        );
    }
}
