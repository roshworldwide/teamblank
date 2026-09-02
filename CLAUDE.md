# SENTINELWIPE

Forensic sanitization and recovery for SIH 2026 · PS 26149 · NTRO.

## The claim we are defending

Every sanitization tool on the market asserts that it worked. We prove it by
attacking our own output with our own recovery engine and publishing the result.
Erasure and recovery are the same instrument pointed in two directions.

## The demo, which is the spec

1. Mount a 256 MB image containing 40 planted files of known SHA-256.
2. Carve. Recover 40/40 with confidence scores. **Recovery engine works.**
3. Wipe with the method appropriate to the medium. Live sector telemetry.
4. Carve the same image again. Recover 0/40. **Erasure works, and we proved it
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
6. **Reproducible.** `make demo` from a fresh clone produces byte-identical
   certificates given the same fixture seed.

## Standards mapping — cite, do not paraphrase

Every sanitization claim carries its clause: NIST SP 800-88 Rev. 1 (Clear / Purge /
Destroy), IEEE 2883-2022, and where legacy is expected, DoD 5220.22-M. Maintain
docs/standards_map.md as a table: our operation → the standard → the clause →
what we verified → what we could not. An officer will read this table before they
read the code.

## Visual law — INSTRUMENT, not product

This is equipment, not a landing page. The reference is an oscilloscope and a
forensic workstation, not a SaaS dashboard.

Palette, and nothing outside it:
  --void      #07090A   canvas
  --panel     #0D1113   surfaces
  --line      #1A2226   dividers, grid
  --dim       #4A5A61   inert text, disabled sectors
  --read      #A8BEC6   body text
  --live      #35E08A   phosphor — active telemetry, verified states, ONLY
  --warn      #E0A030   amber — degraded, unverifiable, partial
  --destroy   #E0483C   red — destructive operations and failed verification
  --seal      #48C8E0   cyan — signed, chain-anchored, immutable

Rules:
- Monospace for every number. Tabular figures. Numbers never reflow.
- --live is the only saturated colour in a resting frame. It marks what is
  happening right now and nothing else.
- --destroy appears only during and after destructive operations. Never decorative.
- No gradients except the entropy heat ramp. No shadows except one 1px inset on
  panels. No rounded corners above 4px — this is not a consumer app.
- Density is the aesthetic. Empty space reads as an unfinished student project;
  packed, aligned telemetry reads as an instrument.
- Animate only transform and opacity. The sector map is canvas; never DOM nodes.
- Nothing is ever centred. Left-aligned, grid-locked, engineering drawing.

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
