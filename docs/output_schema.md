# The carve report schema — `sentinelwipe.carve.report/1`

**Frozen 2026-09-03.** This is the contract between the carve engine and everything
that reads it: the Tauri frontend, the certificate writer, the acceptance table, and
the pre-wipe/post-wipe diff. It is the wire format, and it is fixed before
`core/carve/src/carve.rs` is written, so the instrument can be built in full against
the golden sample while the engine is still landing.

Changing a field name, a type, or an enum value after this point carries the same
ceremony as changing a confidence weight: it is announced, it moves the `schema`
string, and the golden sample and the frontend move in the same commit.

A frontend developer should never need to open a `.rs` file. If something here is
ambiguous, that is a defect in this document.

---

## 1 · The golden sample, and how it was made

`fixtures/sample_output.json` — sha256
`28356843de8c14b0240747e11da085e283865c4cc872d8e2431f3028dd14127d`, 89,773 bytes,
56 records.

It is **generated, never hand-written.** CLAUDE.md rule 2 admits no illustrative
values, not even in a mock, so every number in it was measured:

| what | where it came from |
|---|---|
| paths, kinds, offsets, extents, sizes, SHA-256 | `out/fixture.manifest.json`, read at generation time |
| the four confidence terms and the composite | the shipped `confidence::confidence` |
| `structure.valid` / `end_relative` / `score` / `detail` | the shipped `structure::validate` |
| the gate, the weights, the ladder rungs, the breach point | `confidence.rs` consts, read — never literals |
| every `sha256` field | SHA-256 over the bytes the record's own `extents` name |

Regenerate it:

```
cd core && cargo run --release -p sentinelwipe-carve --example gen_sample_output
```

The generator is **`core/carve/examples/gen_sample_output.rs`**. It is committed,
it takes no arguments, it reads `out/fixture.img` and `out/fixture.manifest.json`,
and it writes `fixtures/sample_output.json` and nothing else. It refuses to write a
file it did not measure: a missing fixture is a hard failure naming both paths.

**Its self-check.** SHA-256 is hand-rolled there (CLAUDE.md forbids a new
dependency; `crc32` in `structure/mod.rs` sets the precedent) and is not trusted on
its own. Before writing anything, the generator hashes the bytes it assembled for
each of the 35 planted carvable objects and asserts the digest equals the one
`fixtures/build_image.py` independently recorded in the manifest. **35 of 35 match.**
That one assertion proves the hash implementation, proves the extents were assembled
in the right order, and proves each validator's `end` landed exactly on the object's
last byte. It also asserts, per record, that the four weighted terms sum to the
composite to within 1e-12.

**It is byte-reproducible.** Two consecutive runs against the frozen fixture produce
identical files. There are no timestamps, no durations, no host paths and no map
iteration order in the output; records are sorted by `offset` ascending, then `kind`.

**What the sample is not.** `provenance.is_carve_run` is `false`. `carve.rs` did not
exist when this file was frozen, so the sample is not the output of a carve run and
its record set is not a recovery result. See §8 before rendering any count from it as
recall.

---

## 2 · File conventions

- UTF-8, LF line endings, two-space indent, trailing newline.
- **Every float is serialized with exactly six decimal places** — `0.900000`,
  `0.285714`. There are no exceptions and no scientific notation. Display precision
  is the UI's choice; the project convention is four places (`0.9000`).
- No `NaN`, no `Infinity`. `confidence::clamp01` maps NaN to `0.000000` upstream, so
  a score that reaches this file always compares against a threshold.
- Byte offsets and lengths are **unsigned integers, in bytes, absolute within the
  image**, unquoted, never floats.
- `null` is a real value with a meaning per field, never a stand-in for zero.
- Key order is stable across runs. Consumers should not depend on it.

---

## 3 · Top-level shape

```
{
  "schema":             string
  "provenance":         object
  "run":                object
  "policy":             object
  "kind_policy":        object   keyed by kind
  "counts":             object
  "score_distribution": object
  "margin":             object
  "ground_truth":       object | null
  "candidates":         array of record objects
}
```

All ten keys are **required and always present**. `ground_truth` is the only one that
may be `null`, and only when the run had no manifest to compare against.

---

## 4 · The blocks

### 4.1 `schema` — string, required

Exactly `"sentinelwipe.carve.report/1"` for this version. A reader must reject a
report whose major version it does not know rather than parse it optimistically.

### 4.2 `provenance` — object, required

Who produced this file and what it is. This block exists so a report can never be
mistaken for a run it was not.

| field | type | meaning |
|---|---|---|
| `producer` | string | the program that wrote the file. Sample: `core/carve/examples/gen_sample_output.rs` |
| `command` | string | the exact command that reproduces it |
| `is_carve_run` | bool | `true` only when the engine scanned an image and reported what it found. `false` in the golden sample |
| `notes` | array of string | free text, may be empty. Verification limits and caveats belong here (CLAUDE.md rule 1) |

The sample carries six notes. They are load-bearing, not decoration: they state that
the file is generated, that it is not a carve run, that `counts.admitted` is not
recall, that reachability and demonstrated recall are different fields, that the
residue span for footerless decoys is a policy choice, and that `timing` is null so
the file regenerates byte-identically. **The UI should surface `notes` wherever it
surfaces the counts.**

### 4.3 `run` — object, required

The image identity. This is the join key for the pre-wipe/post-wipe diff.

| field | type | units / range | optional | meaning |
|---|---|---|---|---|
| `phase` | string | `"pre-wipe"` \| `"post-wipe"` \| `"standalone"` | no | which carve of the demo loop this is |
| `image_path` | string | — | no | path as given, **relative to the repo root**. Never absolute; a report must not carry a laptop's directory layout |
| `image_bytes` | integer | bytes, ≥ 0 | no | size of the image read |
| `image_sha256` | string | 64 lowercase hex | no | digest of the whole image **as read**. This is what changes between the pre-wipe and post-wipe reports and it is what proves the two reports describe the same medium in two states |
| `read_mode` | string | `"file"` \| `"device"` | no | `"file"` always for the internal round. D1: nothing is mounted, the carver reads a file |
| `device` | string \| null | — | yes | device path when `read_mode` is `"device"`; `null` otherwise |
| `timing` | object \| null | — | yes | `null`, or `{"started_utc": string, "elapsed_ms": integer, "bytes_read": integer}`. **`null` in the golden sample on purpose**: a duration is the one field that would stop the sample regenerating byte-identically |

### 4.4 `policy` — object, required

The published confidence function and the gate, **as the run actually used them**.
Every value is read from a `confidence.rs` const at generation time. A report always
carries the parameters it was scored under, so a score can be re-derived years later
without the binary that produced it.

| field | type | value in the sample | meaning |
|---|---|---|---|
| `formula` | string | see below | the formula, assembled from the weight consts so it cannot drift from them |
| `weights.signature_integrity` | float [0,1] | `0.400000` | `W_SIGNATURE` |
| `weights.structural_validity` | float [0,1] | `0.350000` | `W_STRUCTURE` |
| `weights.entropy_consistency` | float [0,1] | `0.150000` | `W_ENTROPY` |
| `weights.size_plausibility` | float [0,1] | `0.100000` | `W_SIZE` |
| `weights_sum` | float | `1.000000` | the four weights added. A reader may assert this is 1 |
| `min_confidence` | float [0,1] | `0.750000` | `confidence::MIN_CONFIDENCE`, **the admission gate** |
| `non_structure_ceiling` | float [0,1] | `0.650000` | `W_SIGNATURE + W_ENTROPY + W_SIZE`: the most a candidate can score with no structural evidence at all |
| `structural_breach_point` | float [0,1] | `0.285714` | `(min_confidence − non_structure_ceiling) / W_STRUCTURE`: the structural credit at which a candidate holding the ceiling would be admitted |
| `signature_ladder` | object | 4 rungs | rung name → its value, see §5.1 |
| `entropy_min_sample_bytes` | integer, bytes | `1024` | below this length term 3 is not measured |
| `entropy_unknown` | float [0,1] | `0.500000` | the value term 3 takes when the object is shorter than that. An explicit "no information" marker, not a score |

```
confidence = 0.40*signature_integrity + 0.35*structural_validity
           + 0.15*entropy_consistency + 0.10*size_plausibility
```

### 4.5 `kind_policy` — object, required

Keyed by the seven kind strings: `JPEG`, `PNG`, `PDF`, `ZIP`, `SQLITE`, `MP4`,
`GZIP`. The per-kind constants terms 3 and 4 were scored against, hoisted here rather
than repeated on 56 records. Present for every kind the carver knows, whether or not
a record of that kind appears.

| field | type | meaning |
|---|---|---|
| `defines_footer` | bool | whether the format publishes a terminating signature. `false` for GZIP, MP4 and SQLITE, which is why term 1 caps at `0.75` for them |
| `entropy_band_bits_per_byte` | array of 4 floats | `[lo_zero, lo_full, hi_full, hi_zero]`, in bits per byte, range [0,8]. A trapezoid: term 3 is 0 at or below `lo_zero`, rises linearly to 1 at `lo_full`, is flat to `hi_full`, falls linearly to 0 at or above `hi_zero`. JPEG in the sample: `[5.5, 7.0, 7.99, 8.0]` |
| `size_bounds_bytes` | array of 4 integers | `[zero_lo, full_lo, full_hi, zero_hi]`, in bytes. The same trapezoid, interpolated on log2(bytes) because format size ranges are multiplicative. `zero_lo` is the format's structural floor — below it the object cannot exist. JPEG in the sample: `[107, 1024, 16777216, 67108864]` |

Both arrays are non-decreasing. A UI can render the band and the measured value on
the same axis without consulting anything else.

### 4.6 `counts` — object, required

Literally counted from `candidates`. Nothing here is derived from ground truth except
where the field name says so.

| field | type | sample | meaning |
|---|---|---|---|
| `records` | integer ≥ 0 | `56` | `candidates.length` |
| `admitted` | integer ≥ 0 | `35` | records with `admitted: true` |
| `rejected` | integer ≥ 0 | `21` | records with `admitted: false`. `admitted + rejected == records` |
| `sha256_matches_planted` | integer ≥ 0 | `35` | records whose `ground_truth.sha256_matches` is `true`. **Not a recall figure** — see §8 |
| `by_kind` | object | 7 keys | kind → `{records, admitted, rejected}`. Only kinds with at least one record appear |
| `by_assembly` | object | 3 keys | assembly value → count. Always all three keys, zeroes included. Sample: `contiguous 28`, `reassembled 7`, `signature-span 21` |

### 4.7 `score_distribution` — object, required

`admitted` and `rejected`, each `{n: integer, min: float, max: float, mean: float}`
over `confidence.total`. Measured on the sample:

```
admitted   n=35   min 0.900000   max 1.000000   mean 0.957143
rejected   n=21   min 0.518570   max 0.650000   mean 0.580502
```

When a population is empty — a post-wipe carve that recovers nothing — the block is
still present; a reader must handle `n: 0` and must not divide by it. This is the
empty-table state.

### 4.8 `margin` — object, required

The separation story, computed per run. This is what the UI's confidence panel
explains, and it is the block an examiner reads first.

| field | type | sample | meaning |
|---|---|---|---|
| `lowest_admitted` | float [0,1] | `0.900000` | the weakest thing that got through |
| `highest_rejected` | float [0,1] | `0.650000` | the strongest thing that did not |
| `population_gap` | float | `0.250000` | `lowest_admitted − highest_rejected`. **A distance, not a guarantee. Nothing enforces it** |
| `gate_headroom` | float | `0.100000` | `min_confidence − highest_rejected` |
| `worst_rejected_structural_validity` | float [0,1] | `0.250000` | the most structural credit any rejected record earned |
| `structural_breach_point` | float [0,1] | `0.285714` | repeated from `policy` so this block stands alone |
| `structural_headroom` | float | `0.035714` | `structural_breach_point − worst_rejected_structural_validity`. **The margin that actually binds** |
| `binds` | string | `"structural_headroom"` | names the field above that is the real margin, so a renderer cannot pick the flattering one |

A record already holding full marks on signature, entropy and size carries
`non_structure_ceiling` = 0.65 for free, and is admitted the moment its structural
credit reaches `structural_breach_point`. **Quote `structural_headroom` = 0.0357, not
`population_gap` = 0.2500.** Architecture §D2 has the derivation and the mutation
test that confirms it.

### 4.9 `ground_truth` — object or null, required key

Present when the run was given a fixture manifest to compare against; `null` for a
carve of an image whose contents are not known in advance. **Nothing in `candidates`
depends on this block existing** — a carver that has never seen a manifest produces a
schema-valid report.

| field | type | sample | meaning |
|---|---|---|---|
| `manifest_path` | string | `out/fixture.manifest.json` | repo-relative |
| `manifest_sha256` | string, 64 hex | `1808494e…dbc2cd69` | digest of the manifest as read |
| `planted_total` | integer | `40` | files the fixture planted |
| `reachability` | object | see below | **a ceiling, not a result** |
| `reachability.contiguous` | integer | `28` | planted files a contiguous engine could reach at all (manifest `expected_recoverable: "signature-only"`) |
| `reachability.needs_bifragment_reassembly` | integer | `5` | reachable only with `bifragment.rs` |
| `reachability.unreachable_by_construction` | integer | `7` | reachable by nothing this carver does |
| `unreachable` | array | 7 entries | one `{path, kind, reason}` per unreachable file |
| `recall_measured` | bool | `false` | whether a carve run produced a recall figure |
| `demonstrated_recall` | object \| null | `null` | see §8 |
| `demonstrated_recall_note` | string | — | why it is null, or how it was measured |

`unreachable[].reason` is **derived from the manifest row**, not asserted by name.
The three shapes that occur, verbatim from the sample:

- `kind TXT has no row in signature::SIGNATURES: no header to scan for` — 5 files
- `3 extents; bifragment gap carving reassembles at most 2` — 1 file
- `2 extents stored out of physical order (extent[1] at 214110208 precedes extent[0] at 214231040); a forward gap search cannot reach them` — 1 file

When `demonstrated_recall` is non-null it is
`{recovered: integer, of: integer, method: string}` and `recall_measured` is `true`.

---

## 5 · The record — one entry in `candidates`

Every field is required. `reason_code`, `reason`, `ground_truth` and
`structure.end_relative` are the four that may be `null`.

| field | type | units / range | meaning |
|---|---|---|---|
| `id` | string | `"<KIND>@<offset>"` | stable within a run; **the join key for the pre-wipe/post-wipe diff.** Sample: `"JPEG@18325159"` |
| `kind` | string | one of the 7 | the detected type. `DOCX` is a ZIP container and is detected as `ZIP`; the manifest's own label is in `ground_truth.manifest_kind` |
| `offset` | integer | bytes, absolute in the image | first byte of the object, `== extents[0].offset` |
| `length` | integer | bytes, > 0 | total recovered bytes, `== sum(extents[].length)`. This is the number of bytes hashed into `sha256` |
| `extents` | array | 1..n of `{offset, length}` | the physical byte ranges, **in logical order**. One entry means contiguous. Multiple entries may be out of physical order. This is what drives the sector map |
| `assembly` | string | see §5.3 | how the extent list was arrived at |
| `sha256` | string | 64 lowercase hex | digest of the recovered bytes, in logical order |
| `signature` | object | §5.1 | the signature layer's two observations |
| `structure` | object | §5.2 | the format walker's verdict, verbatim |
| `entropy.bits_per_byte` | float | [0,8] | Shannon entropy of the recovered bytes. Always reported |
| `entropy.sampled` | bool | — | `length >= policy.entropy_min_sample_bytes`. When `false`, term 3 is `policy.entropy_unknown` regardless of this measurement |
| `confidence` | object | §6 | the four terms, their weighted contributions, and the composite |
| `admitted` | bool | — | `confidence.total >= policy.min_confidence`. See §7 |
| `reason_code` | string \| null | §7 | machine-groupable rejection cause. `null` when `admitted` |
| `reason` | string \| null | — | one line for the operator. `null` when `admitted` |
| `ground_truth` | object \| null | §5.4 | the manifest entry this record was matched to, or `null` |

### 5.1 `signature`

| field | type | meaning |
|---|---|---|
| `header_matched` | bool | the format's magic bytes matched exactly at `offset` |
| `footer_defined` | bool | the format publishes a terminator at all. Equal to `kind_policy[kind].defines_footer` |
| `footer_found` | bool | the terminator was found **in sequence** after the header, within `length`. Always `false` when `footer_defined` is `false` |
| `ladder_rung` | string | the named rung term 1 landed on |

The four rungs and their values, from `policy.signature_ladder`:

```
header-mismatch     0.00   header did not match exactly            (gate: nothing else is scored)
header-only         0.50   header exact; terminator defined; none in sequence
no-footer-defined   0.75   header exact; format defines no terminator   (ceiling for that kind)
header-and-footer   1.00   header exact; terminator defined and found in sequence
```

The sample exercises two of the four: `header-and-footer` 28 records,
`no-footer-defined` 28 records. `header-only` and `header-mismatch` do not occur on
this fixture; the UI must still handle them.

### 5.2 `structure`

Taken from `structure::validate` and passed through unmodified.

| field | type | meaning |
|---|---|---|
| `valid` | bool | the **hard gate**: this is an object of this kind and its extent is known. It is never a thresholded score, and it is **not** the admission decision |
| `end_relative` | integer \| null | bytes **relative to the object's first byte**, one past its last byte. `null` when no end could be established — 21 of 21 rejected records in the sample. Not an absolute offset: add `offset` for that, and only when `assembly` is `contiguous` |
| `score` | float [0,1] | the validator's rubric total. Each validator publishes a fixed list of weighted structural checks summing to 1.0. This value is term 2 verbatim |
| `detail` | string | one line, machine-greppable, naming what was checked and what failed. Never says "invalid" without naming the check and the offset |

`detail` is a real string from the validator, never generated for display. All 21
rejected records in the sample carry 21 **distinct** detail strings, for example:

```
jpeg: expected a marker at offset 39375, found 00
gzip: FLG is 0x99, reserved bits 5-7 are 0x80 and RFC 1952 requires them zero
gzip: header parsed over 10 bytes but the DEFLATE stream failed: distance 31 reaches 27 bytes behind the start of output
```

and on an accepted object it says what it proved:

```
gzip: 28-byte header naming 'carve_session.log', 109146 DEFLATE bytes in 1 block(s) -> 393656 bytes, CRC-32 7D84AEC6 verified, ISIZE 393656 matched, 109182 total
```

Render it as-is. It is the sentence that answers "why did the number come out that
way", and paraphrasing it loses the offset.

### 5.3 `assembly` — how the byte range was established

| value | meaning | sample |
|---|---|---|
| `contiguous` | one extent; the structure validator established the end | 28 |
| `reassembled` | more than one extent, joined across a gap. Requires `bifragment.rs` | 7 |
| `signature-span` | the structure validator established **no** end. The span runs from the header to the format's terminator when the scanner found one, and otherwise to a fallback window | 21 |

`signature-span` is the shape residue takes. Every `signature-span` record in the
sample is residue, and its window is the largest planted object of that kind — the
span `tests/residue_separation.rs` uses, which architecture §D2 names as a policy
choice. Only the adversarial ceiling of 0.6500, with terms 3 and 4 pinned to 1.0 for
every decoy, is safe to quote against a challenge to that choice.

### 5.4 `ground_truth` (per record)

`null` unless the record was matched to a manifest entry.

| field | type | meaning |
|---|---|---|
| `path` | string | the planted file's path inside the fixture filesystem |
| `manifest_kind` | string | the manifest's own label, which can differ from `kind`: `DOCX` here, `ZIP` there |
| `expected_recoverable` | string | `"signature-only"` \| `"bifragment"` \| `"unrecoverable-by-design"`, verbatim from the manifest |
| `sha256_matches` | bool | the record's `sha256` equals the manifest's digest for that file — the recovered bytes **are** the planted file |

---

## 6 · `confidence` — the four terms, and the arithmetic

```
"confidence": {
  "signature_integrity": float [0,1],
  "structural_validity": float [0,1],
  "entropy_consistency": float [0,1],
  "size_plausibility":   float [0,1],
  "weighted": {
    "signature_integrity": float,
    "structural_validity": float,
    "entropy_consistency": float,
    "size_plausibility":   float
  },
  "total": float [0,1]
}
```

The four top-level terms are the **raw** term values, each independently computed and
independently unit tested. `weighted.<term>` is that term multiplied by
`policy.weights.<term>`.

**The four weighted terms sum to the composite.** This is a published property, not a
coincidence, and the generator asserts it on every record to within 1e-12:

```
total = weighted.signature_integrity
      + weighted.structural_validity
      + weighted.entropy_consistency
      + weighted.size_plausibility

      = 0.40 * signature_integrity
      + 0.35 * structural_validity
      + 0.15 * entropy_consistency
      + 0.10 * size_plausibility
```

**This is why the stacked bar works.** Render the four `weighted` values as four
segments; their lengths add to `total` on a 0..1 axis, and the gate at
`policy.min_confidence` is a rule drawn on that same axis. A UI that stacks the raw
terms instead will draw a bar of length up to 4.0 that means nothing. Use `weighted`
for geometry and the raw term for the tooltip.

Three worked examples, all real records from the golden sample.

**`ZIP@1069056` — a perfect object, `total` 1.000000**

```
0.40 × 1.000000  =  0.400000     header exact, EOCD found in sequence
0.35 × 1.000000  =  0.350000     ooxml entries=7 xcheck=7/7 payload=7/7 cd@78930 end=79397
0.15 × 1.000000  =  0.150000     7.887695 bits/byte, inside the ZIP band
0.10 × 1.000000  =  0.100000     79,397 bytes, inside the ZIP bounds
                    --------
                    1.000000     admitted
```

**`GZIP@8054784` — byte-perfect, and still 0.900000**

```
0.40 × 0.750000  =  0.300000     rung no-footer-defined: GZIP publishes no terminator
0.35 × 1.000000  =  0.350000     CRC-32 7D84AEC6 verified, ISIZE 393656 matched
0.15 × 1.000000  =  0.150000     7.870278 bits/byte
0.10 × 1.000000  =  0.100000     109,182 bytes
                    --------
                    0.900000     admitted
```

0.9000 is the **ceiling** for GZIP, MP4 and SQLITE, not a defect in the object. It is
the whole reason `min_confidence` is 0.75 and not 0.90: the fixture plants 15 such
files and a 0.90 gate would discard all 15.

**`JPEG@18325159` — the false-positive story, `total` 0.650000**

```
0.40 × 1.000000  =  0.400000     header exact AND a valid FF D9 found in sequence
0.35 × 0.000000  =  0.000000     jpeg: expected a marker at offset 39375, found 00
0.15 × 1.000000  =  0.150000     7.327992 bits/byte, inside the JPEG band
0.10 × 1.000000  =  0.100000     61,358 bytes, inside the JPEG bounds
                    --------
                    0.650000     rejected: 0.650000 < 0.750000
```

Three of four terms give this blob full marks. At the signature layer it is
indistinguishable from a photograph. **Structure is the only term that rejects it**,
and that is the empirical answer to "why not just match magic bytes?"

---

## 7 · Admission — `admitted`, `reason_code`, `reason`

**The gate is one comparison:**

```
admitted  ==  (confidence.total >= policy.min_confidence)
```

`structure.valid` is **reported but is not a second gate.** Structural evidence
reaches the decision through term 2 and its 0.35 weight, which is what makes
`structural_breach_point` meaningful and testable. A hard `valid` gate on top would
make the published score decorative. A reader may recompute `admitted` from `total`
and `min_confidence` and must get the same answer.

When `admitted` is `false`, `reason_code` and `reason` are both non-null.
When `admitted` is `true`, both are `null`.

| `reason_code` | meaning | in the sample |
|---|---|---|
| `below-min-confidence` | scored under the gate with `structure.valid` true | 0 records |
| `below-min-confidence-structure-invalid` | scored under the gate and the format walker rejected it outright | 21 records |

`reason` is one line, built as:

```
confidence <total, 4dp> below MIN_CONFIDENCE <gate, 4dp>; structure: <structure.detail verbatim>
```

for example

```
confidence 0.5186 below MIN_CONFIDENCE 0.7500; structure: gzip: FLG is 0x99, reserved bits 5-7 are 0x80 and RFC 1952 requires them zero
```

The rejected records are what the false-positive panel is built from: 21 records, 21
distinct validator details, none of them written for display.

---

## 8 · Reachability ceiling and demonstrated recall are two different numbers

They live in two different fields and they must never be rendered as one.

**`ground_truth.reachability`** is a **ceiling**, read off the fixture manifest. It
says what an engine *could* reach on this image if it worked perfectly. On the frozen
fixture: 28 contiguous, 5 needing bifragment reassembly, 7 unreachable by
construction, of 40 planted.

**`ground_truth.demonstrated_recall`** is what a carve run **measurably recovered**.
It is `null` here, with `recall_measured: false`, because no carve run has produced
one — `carve.rs` did not exist when this schema was frozen, and writing a number a
test has not produced is exactly what CLAUDE.md rule 2 forbids.

Consequences for anything rendering this file:

- A contiguous engine — one that does not do bifragment reassembly — is bounded above
  by `reachability.contiguous`. Its result is labelled **"demonstrated recall
  (contiguous engine)"** and it is a measured number, not a ceiling.
- `counts.admitted` = 35 in the golden sample is **not** recall. Seven of those 35 are
  `assembly: "reassembled"`, which needs `bifragment.rs`; two of those seven are files
  the fixture plants as unrecoverable by construction, and their per-record
  `ground_truth.expected_recoverable` says `"unrecoverable-by-design"` so a renderer
  can see it without reading this document. The sample scores them on correctly
  assembled bytes to exercise the schema; it makes no claim that anything recovered
  them.
- `counts.sha256_matches_planted` = 35 is likewise a property of this record set, not
  a recovery rate.
- The seven unreachable files are named individually in `ground_truth.unreachable`,
  each with the reason derived from its manifest row. Naming them on screen is the
  point: an engine that reports its own limits is the claim being defended.

---

## 9 · The same schema, twice: the pre-wipe/post-wipe diff

The demo carves, wipes, and carves the same image again. Both carves emit this
schema, unchanged. Nothing about it is specific to the first run.

- `run.phase` distinguishes them: `"pre-wipe"` then `"post-wipe"`.
- `run.image_path` is identical; `run.image_sha256` differs. That pair is the proof
  the two reports describe the same medium in two states.
- `run.policy` is identical in both, so a difference in scores is a difference in
  bytes and not in the gate.
- Records join on `id` (`<KIND>@<offset>`). A record present pre-wipe and absent
  post-wipe is a recovered object that is gone.
- The post-wipe report is expected to carry `candidates: []`, `counts.records: 0`,
  and `score_distribution.{admitted,rejected}.n: 0`. **That is the empty-table state
  and it is the success case**, not an error: render it as a result, with
  `counts.records` and the diff against the pre-wipe report, never as "no data".
  `min`/`max`/`mean` over an empty population are meaningless — read `n` first.

---

## 10 · Change control

The schema is frozen. To change it: announce it, bump `sentinelwipe.carve.report/1`,
regenerate `fixtures/sample_output.json` with the generator, and update this document
and the frontend in the same commit. A field may not be silently added, because the
golden sample is what the frontend is built against and a sample that lags the engine
is worse than no sample.

Related: `docs/architecture.md` §D2 for the confidence function, its measured
separation and the margin that binds; `core/carve/src/confidence.rs` for the consts
this schema copies; `core/carve/tests/residue_separation.rs` for the CI test that
holds the separation.
