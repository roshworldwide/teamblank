# The wipe report schema — `sentinelwipe.wipe.report/1`

Companion to [`output_schema.md`](output_schema.md), which is the **carve** contract.
Together they are the two artifacts a UI may render. Neither may be supplemented with a
value the engine did not measure (CLAUDE.md rule 2).

Produced by `core/wipe/src/lib.rs::run_job`, written to stdout as one JSON object.
Reproduce any report with the `provenance.command` string it carries.

```
cp out/fixture.img /tmp/copy.img
./core/target/release/wipe --target /tmp/copy.img --allow-root /tmp \
    --i-understand /tmp/copy.img --period-ms 8 --trace /tmp/telemetry.jsonl
```

---

## 1 · Why this document exists

Three of the four instrument views — TARGET, LIVE, VERDICT — have no fields in the carve
contract. `output_schema.md` is titled "The carve report schema" and a grep across its 564
lines returns zero hits for `device`, `telemetry`, `sanitize`, `medium_witness`,
`probe_elapsed_ns`, `deterministic_core` or `measurement_envelope`.

Those fields exist. They are here. Before this document they were emitted without a
contract, which meant a UI binding to them was binding to an undocumented surface.

**What this document does not do:** it does not promise an Ed25519 signature or a Merkle
root, because neither exists yet. `core/ledger` is a one-line stub. Any UI element implying
a signed certificate is rendering a cryptographic claim this engine has never made.

---

## 2 · Top-level shape

15 keys, all required. `sanitize`, `crypto_erase`, `audit.sanitize` and
`dispatch.sanitize_primitive` are `null` on a host-overwrite run — **present and null, not
absent.** A renderer must distinguish "the engine did not do this" from "the engine did not
say."

| key | meaning |
|---|---|
| `schema` | `"sentinelwipe.wipe.report/1"`. Reject an unknown major version. |
| `provenance` | who produced it, the exact command, whether it is a real run |
| `run` | run id, seed, target, resolved target, elapsed |
| `authorization` | the guard's decision and the policy it decided under |
| `device` | the medium's identity — **TARGET binds here** |
| `dispatch` | method chosen, why, NIST category, passes |
| `entropy_bits_per_byte` | before / after / delta, and the estimator that produced them |
| `calibration_probe` | the measured write rate the timing floor is derived from |
| `sanitize` · `crypto_erase` | firmware primitives, `null` unless issued |
| `overwrite` | the host write, per pass — **LIVE binds here** |
| `verification` | sampled or exhaustive read-back, per pass |
| `audit` | the behavioural timing audit — **VERDICT binds here** |
| `telemetry` | the measured stream rate — **LIVE's rate readout binds here** |
| `limits` | array of strings. **Never empty.** Rule 1 lives in this field. |
| `outcome` | the single verdict, and its coverage |

---

## 3 · The blocks a UI binds to

### 3.1 `device` — TARGET

| field | type | value on the fixture | note |
|---|---|---|---|
| `kind` | string | `"image file"` | |
| `model` · `serial` · `firmware` | string | `"unknown"` | **the literal string `unknown`, not null.** A UI must render it as unknown, never blank, never invent one |
| `transport` | string | `"file"` | |
| `identity_source` | string | `"file-metadata"` | how the three fields above were obtained |
| `is_physical_medium` | bool | `false` | if false, no firmware claim on this report means anything |
| `medium` | string | `"image"` | |
| `has_hidden_regions` | bool | `false` | over-provisioning / HPA / DCO. When true, rule 1 forbids a whole-medium claim |
| `logical_sector_bytes` | int | `512` | |
| `physical_sector_bytes` | int \| null | `null` | null when the medium cannot report it |
| `total_sectors` | int | `524288` | |
| `capacity_bytes` | int | `268435456` | exact bytes, never GB |
| `writable` | bool | `true` | |

**There is no bus field and no mount-state field.** The prompt's TARGET screen asks for
both. `transport` is the nearest true thing and it says `"file"`. Nothing is mounted, by
D1 decision — the carver reads a file.

### 3.2 `dispatch` — TARGET's method selector

`method` (`single_pass_zero` · `single_pass_seeded_random_shake128` · `three_pass`),
`method_selected_by`, `passes`, `nist_category` (`"Clear"` · `"Purge"`), `legacy_shape`
(null or `"DoD 5220.22-M"`), `sanitize_primitive` (null or the ATA/NVMe primitive),
`sanitize_selected_by`, and `rationale` — a sentence explaining the choice in prose.

The selector renders from these. **The engine implements three overwrite methods and four
sanitize primitives; the primitives are `simulated` on an image and say so.**

### 3.3 `overwrite` + `telemetry` — LIVE

`overwrite.passes[]` carries per pass: `pass`, `of`, `pattern`, `sectors_written`,
`bytes_written`, `duration_ns`, `sync_ns`, `bytes_per_second`, `chunk_writes`,
`chunk_sectors_first`, `chunk_sectors_final`, `chunk_resizes`, `max_chunk_ns`.

`telemetry` carries the **measured** stream: `period_ms` (requested), `events`, `wall_ms`,
`achieved_hz`, `min_gap_ms`, `max_gap_ms`, `rate_floor_hz`, `met_rate_floor`,
`longest_uninstrumented_interval_ms`.

> `telemetry.note` says it outright: *"met_rate_floor is the verdict, not achieved_hz."*
> **A UI displays `achieved_hz` as the measured rate and `met_rate_floor` as the verdict.**
> On the fixture at `--period-ms 8` the achieved rate is **109.910135 Hz**, not 25 and not
> 23.6. The rate is a property of the run. Hardcoding it is rule 2 violation.

The `--trace` file is JSONL, one `progress` event per frame: `t_ms`, `first_sector`,
`sector_count`, `bytes_done`, `throughput_bps`, `entropy_sample`, `head_sector`, `head_hex`
(256 real bytes under the write head). This is what a sector map animates from.

### 3.4 `audit` — VERDICT

The centrepiece. `audit.overwrite` and `audit.sanitize` share one shape:

| field | meaning |
|---|---|
| `operation` | human string naming the operation audited |
| `code` | `VERIFIED_TIMING` · `UNVERIFIED_TIMING` · `NOT_A_SANITIZATION_CLAIM` |
| `severity` | `verified` · `refused` |
| `simulated` | whether a firmware command was actually issued |
| `device_reported_success` | what the device claimed |
| `return_code_trusted` | **`false`, always.** No return code contributes to any verdict |
| `workload.{kind,capacity_bytes,passes,work_bytes}` | what had to be written |
| `measured_duration_ns` · `_s` | observed elapsed |
| `expected_min_duration_ns` · `_s` | the derived physical floor |
| `ratio_measured_over_expected_min` | measured ÷ floor |
| `threshold_ratio` | `0.05`. Below this the claim is refused |
| `baseline.{source,measured,probe_bytes,probe_elapsed_ns,bytes_per_second,samples_admitted,samples_refused}` | where the rate came from |
| `note` | the whole verdict as one sentence, ready to render |

**The derivation, which is the argument:**

```
expected_min_duration_ns = work_bytes × probe_elapsed_ns ÷ probe_bytes
```

computed in `u128`, truncating downward so rounding always favours the device. It is
**derived, never hardcoded** — a fixed threshold false-positives on fast NVMe.

`baseline.source` is `calibration_probe` or `observed_pass`. `audit.observed_pass_baseline_withheld`
tells a renderer the promotion was refused, and `..._rule` states the rule in prose.

### 3.5 `verification`

`mode` (`sampled` · `exhaustive`), `all_passes_verified`, `coverage_fraction`,
`sectors_verified_min`, `sectors_unverified_max`, `largest_unsampled_run_sectors`, and
per-pass `verdict` (`PATTERN_CONFIRMED_ON_SAMPLE` · `PATTERN_CONFIRMED_WHOLE_MEDIUM` ·
`PATTERN_MISMATCH`), `mismatched_sectors`, `sample_digest_hex`, and `claim` — a full
sentence stating exactly what was and was not verified.

**`largest_unsampled_run_sectors` is the blind spot.** On the fixture it is **2,815
sectors — 0.5369% of the medium.** A region left unwiped inside that run passes a sampled
verdict. A regression test proves both halves. A UI that renders coverage without rendering
this number is rendering half the truth.

### 3.6 `outcome` and `limits`

`outcome.code` is `OVERWRITE_VERIFIED_ON_SAMPLE` or `OVERWRITE_VERIFIED_WHOLE_MEDIUM` —
they are **not** interchangeable, and `whole_medium_claim` (bool) plus `sanitized_scope`
(`sampled_sectors_only` · `whole_medium`) carry the same distinction in two more fields so
a renderer cannot bind a green light to a coverage-blind value.

`limits` is an array of strings and **is never empty**. CLAUDE.md rule 1 lives here:
*"Never leave the limitations section empty."* A UI must surface every entry.

---

## 4 · The two named certificate regions

CLAUDE.md rule 6 splits the certificate into `deterministic_core` and
`measurement_envelope`. **This report does not yet emit them as named objects.** The fields
exist and are listed below; the grouping is a Phase 4 change to this schema.

- **`deterministic_core`** — `run.run_id`, `run.target`, `dispatch.method`, medium witness
  before and after, `medium_unchanged`, every verdict, `outcome`. Byte-identical from a
  fresh clone at the same fixture seed.
- **`measurement_envelope`** — `overwrite.bytes_per_second`, `audit.*.expected_min_duration_ns`,
  `audit.*.measured_duration_ns`, `audit.*.baseline.source`, `.probe_bytes`,
  `.probe_elapsed_ns`. Signed, and explicitly **not** asserted byte-identical: a baseline
  that did not move between runs would mean it was not being measured.

Until Phase 4 lands, a UI may render the two regions as visually distinct **only if it
groups these listed fields itself and says the grouping is the UI's**. It may not claim the
report carries them.

**The medium witness fields** (`medium_witness_before`, `medium_witness_after`,
`medium_unchanged`, `witness_sectors`) appear on the **sanitize** path only, and are present
in `docs/evidence/fake_sanitize_run.txt`. A host-overwrite run carries `sanitize: null` and
therefore no witness.

---

## 5 · Change control

This schema is versioned in `schema`. A field may be added in a minor revision; removing or
retyping one is a major version and a renderer must reject an unknown major.

Every field a UI reads is listed in [`frontend_contract.md`](frontend_contract.md), so a
schema change breaks a documented dependency rather than a silent one.
