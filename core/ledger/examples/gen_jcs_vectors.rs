//! Writes `fixtures/jcs_vectors.json` — the cross-language canonicalization
//! vectors, in the same pattern as `fixtures/guard_vectors.json`: one committed
//! table, exercised by a Rust test AND a Python test, so the two
//! implementations cannot drift apart silently.
//!
//! Direction of truth: for the write guard, Python was the measured original
//! and Rust had to match it. Here it is the mirror image — the Rust module is
//! the reference (it carries the RFC's own sample string and the 10,000-case
//! property test), and `py/sentinelwipe/jcs.py` must reproduce these bytes.
//!
//! The file is ITSELF canonical JCS, produced by the implementation under
//! test. Regenerating it on any platform must be byte-identical; a diff on
//! regeneration is a finding, never noise.

use sentinelwipe_ledger::jcs::corpus::{gen_value, messy, Rng};
use sentinelwipe_ledger::jcs::{canonical, parse, Value};
use std::path::PathBuf;

fn s(x: &str) -> Value {
    Value::Str(x.to_string())
}

fn pair(name: &str, input: String) -> Value {
    // The expectation is derived by the reference implementation itself:
    // parse the messy input, canonicalize, record both.
    let v = parse(input.as_bytes())
        .unwrap_or_else(|e| panic!("vector {name}: input must parse: {e}\n{input}"));
    let canon = String::from_utf8(canonical(&v).expect("canonicalizable")).unwrap();
    Value::obj(vec![
        ("name".into(), s(name)),
        ("input".into(), s(&input)),
        ("canonical".into(), s(&canon)),
    ])
    .unwrap()
}

fn refusal(name: &str, input: &str, class: &str) -> Value {
    use sentinelwipe_ledger::jcs::JcsError as E;
    let got = match parse(input.as_bytes()) {
        Ok(v) => panic!("refusal {name}: parsed as {v:?}"),
        Err(E::FloatRefused { .. }) => "float",
        Err(E::DuplicateKey { .. }) => "duplicate-key",
        Err(E::UnsafeInteger(_)) => "unsafe-integer",
        Err(E::Parse { .. }) => "parse",
    };
    assert_eq!(got, class, "refusal {name}: expected class {class}, got {got}");
    Value::obj(vec![
        ("name".into(), s(name)),
        ("input".into(), s(input)),
        ("error".into(), s(class)),
    ])
    .unwrap()
}

fn main() {
    let mut vectors: Vec<Value> = vec![
        // -- hand-picked edges, each earning its place ----------------------
        pair(
            "rfc-8785-sample-string",
            // §3.2.3's canonical output for the running sample's string field.
            "\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"\\/\"".into(),
        ),
        pair(
            "astral-key-sorts-before-u+e000",
            "{\"\u{e000}\":1,\"\u{10000}\":2}".into(),
        ),
        pair("digit-keys-sort-as-text", "{\"10\":0,\"2\":0,\"1\":0}".into()),
        pair(
            "escaped-and-raw-key-spellings-collapse",
            "{\"\\u0041B\": {\"z\":null, \"a\":[ 1 ,2, -3 ]}}".into(),
        ),
        pair("controls-round-trip", "\"\\u0000\\u001F\\b\\t\\n\\f\\r\\u007F\"".into()),
        pair("solidus-escape-is-erased", "\"a\\/b\"".into()),
        pair("empty-structures", "[{},[],\"\",0]".into()),
        pair(
            "safe-integer-bounds",
            "[9007199254740991,-9007199254740991]".into(),
        ),
        pair("minus-zero-becomes-zero", "-0".into()),
        pair("surrogate-pair-to-raw-utf8", "\"\\uD83D\\uDE00\"".into()),
        pair("whitespace-soup", "  { \"b\" : 1 ,\n\t\"a\" : [ true, null ] }  ".into()),
    ];

    // -- 64 generated cases from the shared deterministic corpus ------------
    let mut r = Rng(0xC0FF_EE00_C0FF_EE00);
    let mut made = 0;
    while made < 64 {
        let v = gen_value(&mut r, 3);
        let mut input = String::new();
        messy(&v, &mut r, &mut input);
        vectors.push(pair(&format!("generated-{made:02}"), input));
        made += 1;
    }

    let n_vectors = vectors.len();
    let refusals = vec![
        refusal("fraction", "1.5", "float"),
        refusal("exponent", "1e3", "float"),
        refusal("negative-zero-float", "-0.0", "float"),
        refusal("float-inside-object", "{\"k\":3.14}", "float"),
        refusal("duplicate-key", "{\"k\":1,\"k\":2}", "duplicate-key"),
        refusal("duplicate-by-escape", "{\"\\u0041\":1,\"A\":2}", "duplicate-key"),
        refusal("beyond-safe-range", "9007199254740992", "unsafe-integer"),
        refusal("lone-high-surrogate", "\"\\uD800\"", "parse"),
        refusal("lone-low-surrogate", "\"\\uDC00\"", "parse"),
        refusal("high-surrogate-wrong-partner", "\"\\uD800\\u0041\"", "parse"),
        refusal("leading-zero", "01", "parse"),
        refusal("trailing-input", "1 2", "parse"),
        refusal("raw-control-in-string", "\"\u{0001}\"", "parse"),
    ];

    let doc = Value::obj(vec![
        ("schema".into(), s("sentinelwipe.jcs_vectors/1")),
        (
            "provenance".into(),
            Value::obj(vec![
                ("generator".into(), s("core/ledger/examples/gen_jcs_vectors.rs")),
                (
                    "command".into(),
                    s("cargo run --release -p sentinelwipe-ledger --example gen_jcs_vectors"),
                ),
                (
                    "reference".into(),
                    s("RFC 8785 (JSON Canonicalization Scheme) \u{a7}3.2.1\u{2013}3.2.4, \
                       integer-only profile: numbers restricted to |n| \u{2264} 2^53\u{2212}1; \
                       floats, NaN and Infinity are refused, never coerced"),
                ),
                (
                    "direction_of_truth".into(),
                    s("Rust (core/ledger/src/jcs.rs) is the reference; \
                       py/sentinelwipe/jcs.py must reproduce these bytes"),
                ),
            ])
            .unwrap(),
        ),
        (
            "notes".into(),
            Value::Arr(vec![
                s("This file is itself canonical JCS, emitted by the implementation under test; \
                   regeneration is byte-reproducible on any platform and a diff is a finding."),
                s("Sorting is by UTF-16 code units (\u{a7}3.2.3): the astral-key vector exists \
                   because code-point and UTF-8 orderings disagree with it above U+FFFF."),
                s("Every refusal is part of the contract: an implementation that accepts one of \
                   these inputs would sign a document with an ambiguous or lossy reading."),
            ]),
        ),
        (
            "counts".into(),
            Value::obj(vec![
                ("vectors".into(), Value::Int(vectors.len() as i64)),
                ("refusals".into(), Value::Int(refusals.len() as i64)),
            ])
            .unwrap(),
        ),
        ("vectors".into(), Value::Arr(vectors)),
        ("refusals".into(), Value::Arr(refusals)),
    ])
    .unwrap();

    let n_refusals = doc
        .get("refusals")
        .and_then(|r| if let Value::Arr(a) = r { Some(a.len()) } else { None })
        .expect("refusals array");
    let bytes = canonical(&doc).expect("the vector file canonicalizes");
    // Self-check before writing: the file must reparse to itself.
    assert_eq!(
        canonical(&parse(&bytes).expect("self-parse")).unwrap(),
        bytes,
        "the vector file is not a fixed point of its own scheme"
    );

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/jcs_vectors.json");
    std::fs::write(&out, &bytes).expect("write fixtures/jcs_vectors.json");
    println!(
        "fixtures/jcs_vectors.json  {} bytes  {} vectors  {} refusals",
        bytes.len(),
        n_vectors,
        n_refusals
    );
}
