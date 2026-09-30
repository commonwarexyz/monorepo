//! Lexer for the core text syntax (DESIGN.md §5.12; see `CORE_SYNTAX.md`).
//!
//! Tokens: identifiers (letters, digits, `_`, `'`, with `::` path
//! separators), numeric literals (decimal or `0x` hex, `_` separators,
//! optional leading `-`, optional width suffix `u8 u16 u32 u64 usize int`),
//! and punctuation. `--` starts a line comment.

use crate::term::{BigInt, Width};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    Ident(String),
    Num(BigInt, Option<Width>),
    Sym(&'static str),
    Eof,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub tok: Tok,
    pub line: u32,
    pub col: u32,
}

const SYMS: [&str; 20] = ["=>", "->", ":=", "::", "(", ")", "[", "]", "{", "}", ",", ";", ":", ".", "|", "@", "#", "/", "=", "*"];

fn ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '\''
}

/// Tokenize `src`.
pub fn lex(src: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let (mut i, mut line, mut col) = (0usize, 1u32, 1u32);
    let advance = |i: &mut usize, line: &mut u32, col: &mut u32, n: usize, chars: &[char]| {
        for _ in 0..n {
            if chars[*i] == '\n' {
                *line += 1;
                *col = 1;
            } else {
                *col += 1;
            }
            *i += 1;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            advance(&mut i, &mut line, &mut col, 1, &chars);
            continue;
        }
        if c == '-' && chars.get(i + 1) == Some(&'-') {
            while i < chars.len() && chars[i] != '\n' {
                advance(&mut i, &mut line, &mut col, 1, &chars);
            }
            continue;
        }
        let (tl, tc) = (line, col);
        // Numbers (optionally negative).
        let neg = c == '-' && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit());
        if c.is_ascii_digit() || neg {
            let mut j = i + neg as usize;
            let hex = chars.get(j) == Some(&'0') && matches!(chars.get(j + 1), Some('x') | Some('X'));
            if hex {
                j += 2;
            }
            let start = j;
            while j < chars.len() && (chars[j].is_ascii_hexdigit() && (hex || chars[j].is_ascii_digit()) || chars[j] == '_') {
                j += 1;
            }
            let digits: String = chars[start..j].iter().filter(|c| **c != '_').collect();
            if digits.is_empty() {
                return Err(format!("{tl}:{tc}: malformed number"));
            }
            let mut n = BigInt::parse_bytes(digits.as_bytes(), if hex { 16 } else { 10 }).ok_or(format!("{tl}:{tc}: malformed number"))?;
            if neg {
                n = -n;
            }
            let sstart = j;
            while j < chars.len() && ident_char(chars[j]) {
                j += 1;
            }
            let suffix: String = chars[sstart..j].iter().collect();
            let w = if suffix.is_empty() {
                None
            } else {
                Some(crate::prim::parse_width(&suffix).ok_or(format!("{tl}:{tc}: unknown literal suffix `{suffix}`"))?)
            };
            out.push(Token { tok: Tok::Num(n, w), line: tl, col: tc });
            let n = j - i;
            advance(&mut i, &mut line, &mut col, n, &chars);
            continue;
        }
        if ident_start(c) {
            let mut j = i;
            loop {
                while j < chars.len() && ident_char(chars[j]) {
                    j += 1;
                }
                // `::` followed by an identifier continues the path.
                if chars.get(j) == Some(&':') && chars.get(j + 1) == Some(&':') && chars.get(j + 2).is_some_and(|c| ident_start(*c)) {
                    j += 2;
                    continue;
                }
                break;
            }
            let s: String = chars[i..j].iter().collect();
            out.push(Token { tok: Tok::Ident(s), line: tl, col: tc });
            let n = j - i;
            advance(&mut i, &mut line, &mut col, n, &chars);
            continue;
        }
        let rest: String = chars[i..(i + 2).min(chars.len())].iter().collect();
        let sym = SYMS.iter().find(|s| rest.starts_with(**s));
        match sym {
            Some(s) => {
                out.push(Token { tok: Tok::Sym(s), line: tl, col: tc });
                advance(&mut i, &mut line, &mut col, s.chars().count(), &chars);
            }
            None => return Err(format!("{tl}:{tc}: unexpected character `{c}`")),
        }
    }
    out.push(Token { tok: Tok::Eof, line, col });
    Ok(out)
}
