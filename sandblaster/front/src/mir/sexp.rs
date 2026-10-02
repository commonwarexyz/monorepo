//! S-expressions: the syntax of `.sbmir` files. TRUSTED (it feeds the
//! literal reading through [`super::ir`], `docs/checked-structuring.md`
//! amendment (d)); a malformed file is an error, never a guess.

/// One S-expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sx {
    /// A bare word: `u16`, `copy`, `42`.
    Atom(String),
    /// A double-quoted string (`\"` and `\\` escapes).
    Str(String),
    List(Vec<Sx>),
}

impl Sx {
    pub fn head(&self) -> Option<&str> {
        match self {
            Sx::List(v) => match v.first() {
                Some(Sx::Atom(a)) => Some(a.as_str()),
                _ => None,
            },
            _ => None,
        }
    }
    /// The elements after the head word.
    pub fn tail(&self) -> &[Sx] {
        match self {
            Sx::List(v) if !v.is_empty() => &v[1..],
            _ => &[],
        }
    }
    pub fn atom(&self) -> Option<&str> {
        match self {
            Sx::Atom(a) => Some(a.as_str()),
            _ => None,
        }
    }
    pub fn str(&self) -> Option<&str> {
        match self {
            Sx::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    /// The first element of the tail with this head: `(k ..)`.
    pub fn field(&self, k: &str) -> Option<&Sx> {
        self.tail().iter().find(|e| e.head() == Some(k))
    }
    pub fn fields<'a>(&'a self, k: &'a str) -> impl Iterator<Item = &'a Sx> + 'a {
        self.tail().iter().filter(move |e| e.head() == Some(k))
    }
    pub fn num(&self) -> Option<u128> {
        self.atom().and_then(|a| a.parse().ok())
    }
}

impl std::fmt::Display for Sx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sx::Atom(a) => write!(f, "{a}"),
            Sx::Str(s) => write!(f, "{s:?}"),
            Sx::List(v) => {
                write!(f, "(")?;
                for (i, e) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{e}")?;
                }
                write!(f, ")")
            }
        }
    }
}

/// Parses a sequence of top-level S-expressions (`;` starts a comment to
/// the end of the line).
pub fn parse(text: &str) -> Result<Vec<Sx>, String> {
    let b = text.as_bytes();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut stack: Vec<Vec<Sx>> = vec![Vec::new()];
    while i < b.len() {
        let c = b[i];
        match c {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => i += 1,
            b';' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'(' => {
                stack.push(Vec::new());
                i += 1;
            }
            b')' => {
                if stack.len() < 2 {
                    return Err(format!("line {line}: unbalanced `)`"));
                }
                let v = stack.pop().unwrap();
                stack.last_mut().unwrap().push(Sx::List(v));
                i += 1;
            }
            b'"' => {
                let mut s = String::new();
                i += 1;
                loop {
                    if i >= b.len() {
                        return Err(format!("line {line}: unterminated string"));
                    }
                    match b[i] {
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\\' if i + 1 < b.len() => {
                            s.push(b[i + 1] as char);
                            i += 2;
                        }
                        _ => {
                            // multi-byte UTF-8: copy the whole character
                            let ch = text[i..].chars().next().unwrap();
                            s.push(ch);
                            i += ch.len_utf8();
                        }
                    }
                }
                stack.last_mut().unwrap().push(Sx::Str(s));
            }
            _ => {
                let st = i;
                while i < b.len() && !matches!(b[i], b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' | b'"' | b';') {
                    i += 1;
                }
                stack.last_mut().unwrap().push(Sx::Atom(text[st..i].to_string()));
            }
        }
    }
    if stack.len() != 1 {
        return Err("unbalanced `(` at end of file".into());
    }
    Ok(stack.pop().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_nested_lists_strings_and_comments() {
        let v = parse("(a \"b c\" (d 1)) ; x\n(e)").unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].head(), Some("a"));
        assert_eq!(v[0].tail()[0], Sx::Str("b c".into()));
        assert_eq!(v[0].field("d").unwrap().tail()[0].num(), Some(1));
        assert!(parse("(a").is_err());
        assert!(parse("a)").is_err());
    }
}
