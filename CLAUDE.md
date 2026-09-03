# SENTINELWIPE

Forensic sanitization and recovery for SIH 2026 · PS 26149 · NTRO.

## The claim we are defending

Every sanitization tool on the market asserts that it worked. We prove it by
attacking our own output with our own recovery engine and publishing the result.
Erasure and recovery are the same instrument pointed in two directions.

## The demo, which is the spec

1. Open a 256 MB image containing 40 planted files of known SHA-256. Nothing is
   mounted: the carver reads bytes, so the image is a file, never an attached device.
2. Carve. Recover 28 of 40 byte-exact, with confidence scores. Twelve are not
   recovered and each has a stated reason: five plaintext files carry no signature,
   five need fragment reassembly, and two we fragmented deliberately to defeat our
   own engine. **Recovery engine works, and reports its own limits.**
3. Wipe with the method appropriate to the medium. Live sector telemetry.
4. Carve the same image again. Recover 0 of 40. **Erasure works, and we proved it
   with the tool that would have found it.**
5. Sign the certificate. Append to the Merkle chain.
6. Tamper with one byte of the certificate. Verification goes red.

Nothing that does not serve those six steps gets built before the internal round.

## Scope discipline — read before proposing anything

IN, for the internal round:
- Loopback images only. Real block devices are gated behind a flag and never demoed.
- Linux device layer. Windows behind the same trait, stubbed, compiling, untested.
- Signature + structure carving. ML carving is a Phase-7 stretch, not a dependency.
- Local Merkle chain with Ed25519. Not Fabric.

OUT until nationals, and say so on the slide rather than building it:
- Hyperledger Fabric, GPU carving, APFS, multi-terabyte scanning, live TRIM analysis.

## Stack — locked

| Layer | Choice | Why |
|---|---|---|
| Engine | Rust, one workspace | memory-safe on raw byte handling; a jury word that lands |
| Orchestration | Python 3.11 + uv + typer | fast to move, lockfile reproducible |
| Carving reference | The Sleuth Kit for cross-check only | we implement carving ourselves; TSK validates us |
| Ledger | ed25519-dalek + sha2, hand-rolled Merkle | ~120 lines, explainable line by line under questioning |
| Desktop | Tauri v2 + React + TypeScript | 12 MB binary, offline, no Chromium bundle — these are jury triggers |
| Telemetry | Rust → Tauri events → React | live, not polled |
| Charts | canvas + hand-written SVG | no chart library; the sector map is 100k blocks |
| Tests | pytest + cargo test | |

Never add a dependency without telling me first.

## Non-negotiable engineering rules

1. **The tool never claims more than it verified.** If SSD over-provisioning means
   we cannot prove purge, the certificate says so in that field. NIST SP 800-88
   itself advises stating verification limits. Claiming a clean wipe we did not
   verify is the one failure that ends this project's credibility.
2. **Every number on screen traces to a measurement.** No illustrative values, no
   placeholder percentages, anywhere, ever — not even in a mock.
3. **Confidence scores are computed, not asserted.** confidence = f(signature
   integrity, structural validity, entropy profile). Publish the function.
4. **Destructive operations require an explicit typed confirmation** naming the
   target, and refuse to run against any device not on an allowlist. A forensics
   tool that can wipe the demo laptop is a disqualifying defect.
5. **The behavioural audit is real.** Time every sanitize command. A 1 TB "erase"
   completing in 200 ms means the drive lied; flag it, never trust the return code.
6. **Reproducible, in a declared region.** The certificate is split into two named
   regions and BOTH are inside the Ed25519 signature and the Merkle chain.
   `deterministic_core` — run id, target, method, medium witness before and after,
   medium_unchanged, verdicts, pass/fail — is byte-identical from a fresh clone given
   the same fixture seed, and carries the reproducibility assertion.
   `measurement_envelope` — measured rate, derived floor, observed elapsed,
   baseline.source, probe_bytes, probe_elapsed_ns — is signed but NOT asserted
   byte-identical, because those are real measurements of a real machine and a
   baseline that did not move between runs would mean it was not being measured.
   The certificate states on its face which fields the reproducibility assertion
   covers. Nothing is left outside the signature: an unsigned section is a tamperable
   one, and the timing verdict is the single field most worth forging.

## Standards mapping — cite, do not paraphrase

Every sanitization claim carries its clause: NIST SP 800-88 Rev. 1 (Clear / Purge /
Destroy), IEEE 2883-2022, and where legacy is expected, DoD 5220.22-M. Maintain
docs/standards_map.md as a table: our operation → the standard → the clause →
what we verified → what we could not. An officer will read this table before they
read the code.

## Visual law — INSTRUMENT, not product

This is equipment, not a landing page. The reference is an oscilloscope and a
forensic workstation, not a SaaS dashboard.

**The frontend follows the AURUM design system (Edition 27.0 · Meridian).** AURUM is
the visual authority for everything under `ui/`: the Titanium Codex palette, the type
scale, the 4-point lattice, the Concentricity Law, the motion scale and spring
registry, and the ten G-gates. Where AURUM and this section disagree, AURUM wins.
Where AURUM and a build prompt disagree, AURUM wins. Where AURUM and a schema
disagree, the schema wins — AURUM governs how a number looks, never whether it is true.

Finish: **Aurum Gold**, one finish per product. Note that AURUM Part 12 recommends
Natural Ti for pro instruments and Glacier Ti for telemetry domains "where warmth
would mislead"; gold is a deliberate choice against that grain, and it is paid for by
spending gold only on the human's decision (Part 33) and keeping every measured figure
in titanium and SF Mono.

The rules below are the ones this project adds on top of AURUM, and they still bind:

- Monospace for every number. Tabular figures. Numbers never reflow.
- Numbers are never abbreviated and never animated. `431,059,458 ns`, not "431 ms",
  and never a counting-up animation. A figure carried to a precision the data cannot
  support is detected as bluffing, and the doubt generalises to every other number.
- **Every verdict shows its own arithmetic** — the inputs that produced it, on the same
  screen, at the same time. This is the single rule that separates this UI from a
  dashboard.
- No fake progress, no fake work. No spinner where a count exists. A choreographed
  reveal of an *explanation* is permitted; a delay in front of a *result* is not.
- Density is the aesthetic. Empty space reads as an unfinished student project.
- Animate only transform and opacity. The sector map is canvas; never DOM nodes.
- Nothing is ever centred on an instrument surface. Left-aligned, grid-locked.

The nine-colour palette this section used to specify is superseded by AURUM Part 02.
Its semantics survive in AURUM's four signals: `--live` → patina `#6FAE8F`, `--warn` →
solar `#D98E41`, `--destroy` → oxide `#C96F5E`, `--seal` → glacier `#7FA6C9`.

## Voice

- Name the consequence: "40 of 40 files recovered" not "Scan complete".
- Numerals always. Units always. Precision only to what was measured.
- Never celebrate, never apologise. No "Success!", no "Oops".
- Banned: Simply · Just · Seamless · Powerful · Revolutionary · Something went wrong.
- The certificate reads like a lab report, because it may be read in court.

## Working agreement

- Plan before large changes. Show the plan, wait.
- Small commits. main always runs. `make demo` always works.
- If uncertain between two approaches, say so with the trade-off. Do not build both.
- Log every task and rejection to docs/ai-log/ without being reminded.
