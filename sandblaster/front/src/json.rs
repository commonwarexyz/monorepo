//! A minimal JSON value and writer for the build report (no external
//! dependency; keys keep insertion order).

/// A JSON value.
#[derive(Clone, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(vec![])
    }
    pub fn string(s: &str) -> Json {
        Json::Str(s.to_string())
    }
    /// Inserts a field (objects only).
    pub fn put(&mut self, k: &str, v: Json) {
        if let Json::Obj(fields) = self {
            fields.push((k.to_string(), v));
        }
    }
    pub fn str(&mut self, k: &str, v: &str) {
        self.put(k, Json::string(v));
    }
    pub fn num(&mut self, k: &str, v: i64) {
        self.put(k, Json::Num(v));
    }
    pub fn bool(&mut self, k: &str, v: bool) {
        self.put(k, Json::Bool(v));
    }

    /// Pretty-printed rendering.
    pub fn render(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, 0);
        s.push('\n');
        s
    }

    fn write(&self, out: &mut String, ind: usize) {
        let pad = |n: usize| "  ".repeat(n);
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(&n.to_string()),
            Json::Str(s) => escape(out, s),
            Json::Arr(v) if v.is_empty() => out.push_str("[]"),
            Json::Arr(v) => {
                out.push_str("[\n");
                for (i, x) in v.iter().enumerate() {
                    out.push_str(&pad(ind + 1));
                    x.write(out, ind + 1);
                    if i + 1 < v.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad(ind));
                out.push(']');
            }
            Json::Obj(v) if v.is_empty() => out.push_str("{}"),
            Json::Obj(v) => {
                out.push_str("{\n");
                for (i, (k, x)) in v.iter().enumerate() {
                    out.push_str(&pad(ind + 1));
                    escape(out, k);
                    out.push_str(": ");
                    x.write(out, ind + 1);
                    if i + 1 < v.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad(ind));
                out.push('}');
            }
        }
    }
}

fn escape(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}
