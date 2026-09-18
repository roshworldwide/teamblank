use std::fmt;

pub const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Arr(a), Value::Arr(b)) => a == b,
            (Value::Obj(a), Value::Obj(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                fn sorted(p: &[(String, Value)]) -> Vec<&(String, Value)> {
                    let mut v: Vec<&(String, Value)> = p.iter().collect();
                    v.sort_by(|(x, _), (y, _)| utf16_lt(x, y));
                    v
                }
                sorted(a)
                    .into_iter()
                    .zip(sorted(b))
                    .all(|((ka, va), (kb, vb))| ka == kb && va == vb)
            }
            _ => false,
        }
    }
}
impl Eq for Value {}

#[derive(Debug, PartialEq, Eq)]
pub enum JcsError {
    UnsafeInteger(i64),
    FloatRefused { at: usize },
    DuplicateKey { key: String },
    Parse { at: usize, what: &'static str },
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JcsError::UnsafeInteger(n) => write!(
                f,
                "integer {n} is outside the ECMAScript safe range and cannot be canonicalized losslessly"
            ),
            JcsError::FloatRefused { at } => write!(
                f,
                "float syntax at byte {at}: the signed payload carries no floating point (module docs)"
            ),
            JcsError::DuplicateKey { key } => write!(f, "duplicate object key {key:?}"),
            JcsError::Parse { at, what } => write!(f, "parse error at byte {at}: {what}"),
        }
    }
}

impl Value {
    pub fn obj(pairs: Vec<(String, Value)>) -> Result<Value, JcsError> {
        for (i, (k, _)) in pairs.iter().enumerate() {
            if pairs[..i].iter().any(|(p, _)| p == k) {
                return Err(JcsError::DuplicateKey { key: k.clone() });
            }
        }
        Ok(Value::Obj(pairs))
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

fn utf16_lt(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

pub fn canonical(v: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::with_capacity(256);
    write_value(v, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> Result<(), JcsError> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(n) => {
            if n.abs() > MAX_SAFE_INT {
                return Err(JcsError::UnsafeInteger(*n));
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::Str(s) => write_string(s, out),
        Value::Arr(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Obj(pairs) => {
            let mut order: Vec<&(String, Value)> = pairs.iter().collect();
            order.sort_by(|(a, _), (b, _)| utf16_lt(a, b));
            out.push(b'{');
            for (i, (k, val)) in order.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{0009}' => out.extend_from_slice(b"\\t"),
            '\u{000A}' => out.extend_from_slice(b"\\n"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\u{000D}' => out.extend_from_slice(b"\\r"),
            '\\' => out.extend_from_slice(b"\\\\"),
            '"' => out.extend_from_slice(b"\\\""),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

pub fn parse(input: &[u8]) -> Result<Value, JcsError> {
    let mut p = Parser { b: input, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(JcsError::Parse { at: p.i, what: "trailing input after the document" });
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }
    fn err(&self, what: &'static str) -> JcsError {
        JcsError::Parse { at: self.i, what }
    }
    fn eat(&mut self, lit: &[u8], what: &'static str) -> Result<(), JcsError> {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(self.err(what))
        }
    }

    fn value(&mut self) -> Result<Value, JcsError> {
        match self.b.get(self.i) {
            None => Err(self.err("unexpected end of input")),
            Some(b'n') => self.eat(b"null", "expected null").map(|_| Value::Null),
            Some(b't') => self.eat(b"true", "expected true").map(|_| Value::Bool(true)),
            Some(b'f') => self.eat(b"false", "expected false").map(|_| Value::Bool(false)),
            Some(b'"') => self.string().map(Value::Str),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(c) if c.is_ascii_digit() || *c == b'-' => self.integer(),
            Some(_) => Err(self.err("unexpected byte")),
        }
    }

    fn integer(&mut self) -> Result<Value, JcsError> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        let digits_start = self.i;
        while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
        if self.i == digits_start {
            return Err(self.err("minus sign with no digits"));
        }
        if self.i - digits_start > 1 && self.b[digits_start] == b'0' {
            return Err(self.err("leading zero"));
        }
        match self.b.get(self.i) {
            Some(b'.') | Some(b'e') | Some(b'E') => {
                return Err(JcsError::FloatRefused { at: self.i })
            }
            _ => {}
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).expect("ascii digits");
        let n: i64 = text
            .parse()
            .map_err(|_| JcsError::Parse { at: start, what: "integer overflows i64" })?;
        if n.abs() > MAX_SAFE_INT {
            return Err(JcsError::UnsafeInteger(n));
        }
        Ok(Value::Int(n))
    }

    fn hex4(&mut self) -> Result<u16, JcsError> {
        let s = self
            .b
            .get(self.i..self.i + 4)
            .ok_or(JcsError::Parse { at: self.i, what: "truncated \\u escape" })?;
        let txt = std::str::from_utf8(s)
            .map_err(|_| JcsError::Parse { at: self.i, what: "non-ascii in \\u escape" })?;
        let v = u16::from_str_radix(txt, 16)
            .map_err(|_| JcsError::Parse { at: self.i, what: "bad hex in \\u escape" })?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, JcsError> {
        self.eat(b"\"", "expected opening quote")?;
        let mut s = String::new();
        loop {
            let c = *self.b.get(self.i).ok_or(self.err("unterminated string"))?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(s);
                }
                b'\\' => {
                    self.i += 1;
                    let e = *self.b.get(self.i).ok_or(self.err("truncated escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\u{0008}'),
                        b't' => s.push('\t'),
                        b'n' => s.push('\n'),
                        b'f' => s.push('\u{000C}'),
                        b'r' => s.push('\r'),
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..=0xDBFF).contains(&hi) {
                                self.eat(b"\\u", "high surrogate without its low half")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err(self.err("invalid low surrogate"));
                                }
                                let cp = 0x10000
                                    + ((hi as u32 - 0xD800) << 10)
                                    + (lo as u32 - 0xDC00);
                                s.push(char::from_u32(cp).expect("valid supplementary"));
                            } else if (0xDC00..=0xDFFF).contains(&hi) {
                                return Err(self.err("lone low surrogate"));
                            } else {
                                s.push(char::from_u32(hi as u32).expect("BMP non-surrogate"));
                            }
                        }
                        _ => return Err(self.err("unknown escape")),
                    }
                }
                0x00..=0x1F => return Err(self.err("raw control character in string")),
                _ => {
                    let rest = &self.b[self.i..];
                    let txt = std::str::from_utf8(rest)
                        .or_else(|e| {
                            if e.valid_up_to() > 0 {
                                std::str::from_utf8(&rest[..e.valid_up_to()])
                            } else {
                                Err(e)
                            }
                        })
                        .map_err(|_| self.err("invalid UTF-8"))?;
                    let ch = txt.chars().next().ok_or(self.err("invalid UTF-8"))?;
                    s.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    fn array(&mut self) -> Result<Value, JcsError> {
        self.eat(b"[", "expected [")?;
        let mut items = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(self.err("expected , or ] in array")),
            }
        }
    }

    fn object(&mut self) -> Result<Value, JcsError> {
        self.eat(b"{", "expected {")?;
        let mut pairs: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Value::Obj(pairs));
        }
        loop {
            self.ws();
            let k = self.string()?;
            if pairs.iter().any(|(p, _)| *p == k) {
                return Err(JcsError::DuplicateKey { key: k });
            }
            self.ws();
            self.eat(b":", "expected : after key")?;
            self.ws();
            let v = self.value()?;
            pairs.push((k, v));
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Obj(pairs));
                }
                _ => return Err(self.err("expected , or } in object")),
            }
        }
    }
}


#[doc(hidden)]
pub mod corpus {
    use super::{Value, MAX_SAFE_INT};

    pub struct Rng(pub u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    pub fn gen_string(r: &mut Rng) -> String {
        const POOL: &[&str] = &[
            "a", "A", "0", "9", "\u{e000}", "\u{10000}", "\u{1f600}", "\u{20ac}",
            "\"", "\\", "/", "\n", "\t", "\u{0}", "\u{1f}", "\u{7f}", " ", "क",
        ];
        let len = r.below(6);
        (0..len).map(|_| POOL[r.below(POOL.len() as u64) as usize]).collect()
    }

    pub fn gen_value(r: &mut Rng, depth: u32) -> Value {
        let pick = if depth == 0 { r.below(4) } else { r.below(6) };
        match pick {
            0 => Value::Null,
            1 => Value::Bool(r.below(2) == 0),
            2 => {
                let m = (r.next() % (2 * MAX_SAFE_INT as u64 + 1)) as i64 - MAX_SAFE_INT;
                Value::Int(m)
            }
            3 => Value::Str(gen_string(r)),
            4 => {
                let n = r.below(4);
                Value::Arr((0..n).map(|_| gen_value(r, depth - 1)).collect())
            }
            _ => {
                let n = r.below(4);
                let mut pairs: Vec<(String, Value)> = Vec::new();
                for _ in 0..n {
                    let k = gen_string(r);
                    if !pairs.iter().any(|(p, _)| *p == k) {
                        pairs.push((k, gen_value(r, depth - 1)));
                    }
                }
                Value::Obj(pairs)
            }
        }
    }

    pub fn messy(v: &Value, r: &mut Rng, out: &mut String) {
        let pad = |r: &mut Rng, out: &mut String| {
            for _ in 0..r.below(3) {
                out.push([' ', '\n', '\t'][r.below(3) as usize]);
            }
        };
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Int(n) => out.push_str(&n.to_string()),
            Value::Str(s) => {
                out.push('"');
                for c in s.chars() {
                    let u = c as u32;
                    if c == '"' {
                        out.push_str("\\\"");
                    } else if c == '\\' {
                        out.push_str("\\\\");
                    } else if u < 0x20 {
                        out.push_str(&format!("\\u{u:04x}"));
                    } else if u < 0x80 && r.below(4) == 0 {
                        out.push_str(&format!("\\u{u:04X}"));
                    } else if c == '/' && r.below(2) == 0 {
                        out.push_str("\\/");
                    } else {
                        out.push(c);
                    }
                }
                out.push('"');
            }
            Value::Arr(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    pad(r, out);
                    messy(it, r, out);
                    pad(r, out);
                }
                out.push(']');
            }
            Value::Obj(pairs) => {
                out.push('{');
                for (i, (k, val)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    pad(r, out);
                    messy(&Value::Str(k.clone()), r, out);
                    pad(r, out);
                    out.push(':');
                    pad(r, out);
                    messy(val, r, out);
                    pad(r, out);
                }
                out.push('}');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Value {
        Value::Str(x.to_string())
    }
    fn canon(v: &Value) -> String {
        String::from_utf8(canonical(v).unwrap()).unwrap()
    }

    #[test]
    fn the_rfcs_own_sample_string_serializes_to_its_published_bytes() {
        let raw = "\u{20ac}$\u{000f}\nA'B\"\\\\\"/";
        let expect = "\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"";
        assert_eq!(canon(&s(raw)), expect);
    }

    #[test]
    fn control_characters_use_the_named_escapes_and_lowercase_hex_for_the_rest() {
        assert_eq!(canon(&s("\u{08}\t\n\u{0c}\r")), "\"\\b\\t\\n\\f\\r\"");
        assert_eq!(canon(&s("\u{00}\u{1f}\u{0b}")), "\"\\u0000\\u001f\\u000b\"");
        assert_eq!(canon(&s("\u{7f}")), "\"\u{7f}\"");
        assert_eq!(canon(&s("/")), "\"/\"");
    }

    #[test]
    fn astral_keys_sort_before_u_e000_because_surrogates_do() {
        let v = Value::obj(vec![
            ("\u{e000}".into(), Value::Int(1)),
            ("\u{10000}".into(), Value::Int(2)),
        ])
        .unwrap();
        assert_eq!(canon(&v), "{\"\u{10000}\":2,\"\u{e000}\":1}");
    }

    #[test]
    fn ordering_is_by_code_unit_then_length_and_digits_sort_as_text() {
        let v = Value::obj(vec![
            ("10".into(), Value::Int(0)),
            ("2".into(), Value::Int(0)),
            ("1".into(), Value::Int(0)),
            ("".into(), Value::Int(0)),
            ("a".into(), Value::Int(0)),
            ("a\u{0}".into(), Value::Int(0)),
        ])
        .unwrap();
        assert_eq!(
            canon(&v),
            "{\"\":0,\"1\":0,\"10\":0,\"2\":0,\"a\":0,\"a\\u0000\":0}"
        );
    }

    #[test]
    fn sorting_recurses_into_children_and_never_reorders_arrays() {
        let inner = Value::obj(vec![
            ("b".into(), Value::Int(2)),
            ("a".into(), Value::Int(1)),
        ])
        .unwrap();
        let v = Value::Arr(vec![Value::Int(3), inner, Value::Int(1)]);
        assert_eq!(canon(&v), "[3,{\"a\":1,\"b\":2},1]");
    }

    #[test]
    fn the_safe_range_boundary_is_exact_in_both_directions() {
        assert_eq!(canon(&Value::Int(MAX_SAFE_INT)), "9007199254740991");
        assert_eq!(canon(&Value::Int(-MAX_SAFE_INT)), "-9007199254740991");
        assert_eq!(
            canonical(&Value::Int(MAX_SAFE_INT + 1)),
            Err(JcsError::UnsafeInteger(MAX_SAFE_INT + 1))
        );
        assert_eq!(
            parse(b"9007199254740992"),
            Err(JcsError::UnsafeInteger(9007199254740992))
        );
        assert_eq!(parse(b"9007199254740991"), Ok(Value::Int(MAX_SAFE_INT)));
    }

    #[test]
    fn every_float_spelling_is_refused_never_coerced() {
        for bad in ["1.5", "0.0", "1e3", "1E-2", "[2.0]", "{\"k\":3.14}", "-0.0"] {
            match parse(bad.as_bytes()) {
                Err(JcsError::FloatRefused { .. }) => {}
                other => panic!("{bad:?} must refuse as float, got {other:?}"),
            }
        }
    }

    #[test]
    fn minus_zero_input_canonicalizes_to_zero_like_ecmascript_says() {
        let v = parse(b"-0").unwrap();
        assert_eq!(canon(&v), "0");
    }

    #[test]
    fn duplicate_keys_leading_zeros_and_trailing_input_are_refused() {
        assert!(matches!(
            parse(b"{\"k\":1,\"k\":2}"),
            Err(JcsError::DuplicateKey { .. })
        ));
        assert!(matches!(
            parse(b"{\"\\u0041\":1,\"A\":2}"),
            Err(JcsError::DuplicateKey { .. })
        ));
        assert!(matches!(parse(b"01"), Err(JcsError::Parse { .. })));
        assert!(matches!(parse(b"1 2"), Err(JcsError::Parse { .. })));
    }

    #[test]
    fn lone_surrogate_escapes_terminate_with_an_error_as_the_rfc_demands() {
        for bad in [
            "\"\\ud800\"",
            "\"\\udead\"",
            "\"\\udc00\"",
            "\"\\ud800\\u0041\"",
        ] {
            assert!(
                matches!(parse(bad.as_bytes()), Err(JcsError::Parse { .. })),
                "{bad:?} must error"
            );
        }
        assert_eq!(parse(b"\"\\ud83d\\ude00\"").unwrap(), s("\u{1f600}"));
        assert_eq!(canon(&s("\u{1f600}")), "\"\u{1f600}\"");
    }

    use super::corpus::{gen_value, messy, Rng};
    

    

    

    

    #[test]
    fn ten_thousand_certificates_round_trip_byte_identical() {
        let mut r = Rng(0x5EED_5EED_5EED_5EED);
        for i in 0..10_000u32 {
            let v = gen_value(&mut r, 3);
            let c1 = canonical(&v).unwrap();
            let parsed = parse(&c1).unwrap_or_else(|e| panic!("case {i}: reparse: {e}"));
            let c2 = canonical(&parsed).unwrap();
            assert_eq!(c1, c2, "case {i}: canonical bytes drifted");
            assert_eq!(parsed, v, "case {i}: structure drifted");

            let mut m = String::new();
            messy(&v, &mut r, &mut m);
            let from_messy = parse(m.as_bytes())
                .unwrap_or_else(|e| panic!("case {i}: messy parse: {e}\n{m}"));
            assert_eq!(canonical(&from_messy).unwrap(), c1, "case {i}: messy diverged");
        }
    }

    #[test]
    fn the_property_test_is_not_vacuous() {
        let mut r = Rng(0x5EED_5EED_5EED_5EED);
        let mut kinds = [0u32; 6];
        for _ in 0..10_000 {
            match gen_value(&mut r, 3) {
                Value::Null => kinds[0] += 1,
                Value::Bool(_) => kinds[1] += 1,
                Value::Int(_) => kinds[2] += 1,
                Value::Str(_) => kinds[3] += 1,
                Value::Arr(_) => kinds[4] += 1,
                Value::Obj(_) => kinds[5] += 1,
            }
        }
        assert!(kinds.iter().all(|&k| k > 400), "degenerate generator: {kinds:?}");
    }
    #[test]
    fn the_committed_vectors_are_what_this_implementation_produces() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/jcs_vectors.json");
        let bytes = std::fs::read(&path).expect("fixtures/jcs_vectors.json — run             cargo run --release -p sentinelwipe-ledger --example gen_jcs_vectors");
        let doc = parse(&bytes).expect("the vector file parses under the strict parser");

        assert_eq!(canonical(&doc).unwrap(), bytes, "the committed file is not canonical");

        let arr = |v: &Value| match v {
            Value::Arr(a) => a.clone(),
            _ => panic!("expected array"),
        };
        let st = |v: &Value| match v {
            Value::Str(x) => x.clone(),
            _ => panic!("expected string"),
        };

        let vectors = arr(doc.get("vectors").expect("vectors"));
        let refusals = arr(doc.get("refusals").expect("refusals"));
        assert!(vectors.len() >= 70, "only {} vectors", vectors.len());
        assert!(refusals.len() >= 12, "only {} refusals", refusals.len());

        for v in &vectors {
            let name = st(v.get("name").unwrap());
            let input = st(v.get("input").unwrap());
            let expect = st(v.get("canonical").unwrap());
            let got = String::from_utf8(
                canonical(&parse(input.as_bytes()).unwrap_or_else(|e| {
                    panic!("vector {name}: input no longer parses: {e}")
                }))
                .unwrap(),
            )
            .unwrap();
            assert_eq!(got, expect, "vector {name} drifted");
        }
        for r in &refusals {
            let name = st(r.get("name").unwrap());
            let input = st(r.get("input").unwrap());
            let class = st(r.get("error").unwrap());
            let got = match parse(input.as_bytes()) {
                Ok(v) => panic!("refusal {name} parsed as {v:?}"),
                Err(JcsError::FloatRefused { .. }) => "float",
                Err(JcsError::DuplicateKey { .. }) => "duplicate-key",
                Err(JcsError::UnsafeInteger(_)) => "unsafe-integer",
                Err(JcsError::Parse { .. }) => "parse",
            };
            assert_eq!(got, class, "refusal {name} changed class");
        }
    }
    #[test]
    fn the_python_side_canon_vectors_produce_identical_bytes_here() {
        use sha2::{Digest, Sha256};
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/canon_vectors.json");
        let bytes = std::fs::read(&path).expect("fixtures/canon_vectors.json");
        let doc = parse(&bytes).expect("canon_vectors parses under the strict parser");

        let arr = |v: &Value| match v {
            Value::Arr(a) => a.clone(),
            _ => panic!("expected array"),
        };
        let st = |v: &Value| match v {
            Value::Str(x) => x.clone(),
            _ => panic!("expected string"),
        };
        let int = |v: &Value| match v {
            Value::Int(n) => *n,
            _ => panic!("expected integer"),
        };

        let cases = arr(doc.get("cases").expect("cases"));
        assert!(cases.len() >= 20, "only {} cases", cases.len());
        for c in &cases {
            let name = st(c.get("name").unwrap());
            let canon_str = st(c.get("canonical").unwrap());
            let expect_sha = st(c.get("sha256").unwrap());
            let expect_len = int(c.get("bytes").unwrap());

            let v = parse(canon_str.as_bytes())
                .unwrap_or_else(|e| panic!("case {name}: does not parse here: {e}"));
            let ours = canonical(&v).unwrap();
            assert_eq!(
                ours,
                canon_str.as_bytes(),
                "case {name}: Rust bytes differ from the Python original"
            );
            assert_eq!(ours.len() as i64, expect_len, "case {name}: length drifted");
            let sha = hex::encode_like(Sha256::digest(&ours));
            assert_eq!(sha, expect_sha, "case {name}: digest drifted");
        }
    }
}

#[cfg(test)]
mod hex {
    pub fn encode_like(d: impl AsRef<[u8]>) -> String {
        d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}
