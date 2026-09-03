# SENTINELWIPE

**Forensic data sanitization with adversarial verification.**
Smart India Hackathon 2026 · Problem Statement **26149** · NTRO.

Every sanitization tool on the market asserts that it worked. We prove it: we erase,
then attack the erased media with our own recovery engine, and publish what we found.
Erasure and recovery are the same instrument pointed in two directions.

---

## The result this project exists for

A drive reported `SANITIZE` complete in **1,000 ns**. The tool refused to certify it.

```
measured write rate       622,734,175 B/s        from baseline.source = observed_pass
bytes to overwrite        268,435,456 B
derived physical floor    431,059,458 ns         work_bytes × probe_elapsed_ns ÷ probe_bytes
observed elapsed                1,000 ns
ratio                          0.000002          431,059× faster than physically possible
                                                 VERDICT: UNVERIFIED_TIMING
```

The floor is **derived, never hardcoded** — a fixed threshold would false-positive on fast
NVMe. It is computed in `u128` integer arithmetic, truncating downward so rounding always
favours the device.

A second, independent witness agrees:

```
sectors sampled                   256
medium_witness_before   c82e10f3…7fc9c6
medium_witness_after    c82e10f3…7fc9c6
medium_unchanged                 true            VERDICT: NOT_A_SANITIZATION_CLAIM
```

The command was impossibly fast **and** the bytes it claimed to erase are unchanged.
Raw captured run, with commit and timestamp: [`docs/evidence/fake_sanitize_run.txt`](docs/evidence/fake_sanitize_run.txt).

---

## The one hard thing

Anyone can overwrite a disk. The hard part is proving it, and the loop is the proof:

**carve → wipe → carve again with identical parameters → sign.**

The same engine that recovered the data is turned on the erased medium. If it finds
nothing, that is evidence rather than assertion — because a minute earlier it demonstrably
found things.

Measured on the frozen fixture:

| | before the wipe | after the wipe |
|---|---|---|
| candidates scanned | 58 | 30 |
| **admitted** | **33** | **0** |
| recovered byte-exact | 28 of 40 | 0 of 40 |
| whole-image entropy | 7.061690 bits/byte | 7.999999 bits/byte |

The post-wipe scan is the interesting half. The randomised medium throws up **30 signature
hits**, and structure validation rejects every one. Signature matching alone would have
reported 30 files.

---

## What it does

**1 · Erases** to NIST SP 800-88 Rev. 1 Clear, by a method chosen for the medium.
Single-pass zero, single-pass seeded random, or 3-pass. Firmware primitives (ATA SANITIZE,
NVMe Sanitize, crypto-erase) are dispatched where a device claims them and are **labelled
`simulated` in the field itself** where they are not issued.

**2 · Verifies**, and refuses to be lied to. Sampled read-back after every pass, the
behavioural timing audit above, and a medium witness sampled before and after. No device
return code contributes to any verdict — `return_code_trusted` is `false` in every artifact.

**3 · Carves** files back out of a raw image with no filesystem metadata, and scores every
candidate with a published four-term function:

```
confidence = 0.40·signature_integrity + 0.35·structural_validity
           + 0.15·entropy_consistency + 0.10·size_plausibility
```

Admission gate **0.75**. Seven formats: JPEG, PNG, PDF, ZIP/DOCX, SQLite, MP4, GZIP.
Two-fragment gap carving on a bounded cluster lattice, off by default.

### Why structure carries 0.35

Free space in the fixture carries 21 planted decoys. Scored through shipped code:

```
35 planted, carvable   min 0.9000   max 1.0000   mean 0.9571
21 residue decoys      min 0.5186   max 0.6500   mean 0.5805
                       gap 0.2500, zero overlap
```

Per-term contribution to that separation: signature **+0.0190**, structure **+0.3458**,
entropy **+0.0118**, size **+0.0000**.

**Structure supplies more than the entire gap. Signature supplies nothing.** All 8 residue
JPEGs resolve a valid `FF D9` footer and score a perfect 1.0000 on signature integrity —
identical to the real photographs. At the signature layer a noise blob and a photograph are
indistinguishable. That is the empirical answer to *"why not just match magic bytes?"*

The margin that actually binds is not the 0.2500 population gap. A decoy already holding
full marks on signature, entropy and size carries 0.6500 for free and clears the gate at
structural credit `(0.75 − 0.65) ÷ 0.35 = 0.285714`. The worst decoy sits at **0.2500**, so
the real headroom is **0.0357**. It is enforced in CI.

---

## Cross-checked against The Sleuth Kit

TSK 4.15.0 is the reference, not a competitor. Over the same image:

| | count | which |
|---|---|---|
| both byte-exact | 21 | live, contiguous, signature-bearing |
| TSK only | 7 | 4 live plaintext + 3 live fragmented |
| carver only | 7 | the deleted, contiguous, signature-bearing set |
| neither | 5 | 1 deleted plaintext + 4 deleted fragmented |
| **union** | **35 of 40** | |

**Both tools recover 28 of 40 — and they are not the same 28.** Zero rows disagree on
content. TSK's `icat` reads live files through directory metadata, which is filesystem
parsing rather than carving; the 12 deleted files are metadata-stripped by design, so over
unallocated space `tsk_recover` reports **"Files Recovered: 0"** while our carver pulls
**7 byte-exact** from the same `blkls` stream. TSK 4.15.0 ships no file carver.

Our signature scanner is validated against it: a byte-granular `sigfind` sweep over all 512
intra-sector offsets returns 19 JPEG and 18 GZIP hits, and `carve --no-dedup` emits the
identical offset lists, element for element. Full comparison in
[`docs/tsk_crosscheck.md`](docs/tsk_crosscheck.md), including a section titled *"Where each
tool is worse."*

---

## Standards

| our operation | standard | clause |
|---|---|---|
| single-pass overwrite + read-back | NIST SP 800-88 Rev. 1 | Clear |
| 3-pass overwrite | NIST SP 800-88 Rev. 1 | Clear (legacy DoD 5220.22-M expectation) |
| ATA SANITIZE / NVMe Sanitize / crypto-erase | NIST SP 800-88 Rev. 1 · IEEE 2883-2022 | Purge |
| stating verification limits on the certificate | NIST SP 800-88 Rev. 1 | verification + documentation guidance |

Every claim carries its category, and every row states what we could **not** verify.
Section numbers are deliberately unasserted until checked against the published document.
Full table:
[`docs/standards_map.md`](docs/standards_map.md).

---

## What runs today, and what is architected

| phase | state |
|---|---|
| 1 · Reproducible fixture | **runs** — 256 MiB FAT32, 40 planted files, byte-identical from seed |
| 2 · Carving engine | **runs** — 7 formats, published confidence, two-fragment reassembly |
| 3 · Wipe engine + behavioural audit | **runs** — overwrite passes, sampled read-back, timing audit, 25 Hz telemetry |
| 4 · Adversarial loop, Ed25519 ledger, certificate | **architected, not built** — `core/verify` and `core/ledger` are one-line stubs |
| 5 · Tauri desktop shell | **partial** — `ui/instrument.html` runs the full sequence off recorded artifacts; the Tauri wrapper is not built |
| 6 · Freeze and `make verify` | **not started** — `make test`, `make demo`, `make verify` exit 1 by design rather than reporting success for work not done |

Deliberately **out of scope** until nationals, and said on the slide rather than half-built:
Hyperledger Fabric, GPU carving, APFS, multi-terabyte scanning, live TRIM analysis.
The Windows device layer compiles behind the same `Device` trait and is untested.

---

## Running it

Requires Rust 1.75+, [uv](https://docs.astral.sh/uv/), and Python 3.11 (uv fetches it).

```sh
make fixtures                                   # 256 MiB image + manifest, ~13 s, byte-identical from seed
cd core && cargo build --release                # the carve and wipe binaries

# carve the image and print a JSON report
./core/target/release/carve --phase pre-wipe \
    --manifest out/fixture.manifest.json out/fixture.img

# wipe a COPY. Three flags are required and each one alone stops the run.
cp out/fixture.img /tmp/copy.img
./core/target/release/wipe --target /tmp/copy.img --allow-root /tmp --plan   # prints the resolved path
./core/target/release/wipe --target /tmp/copy.img --allow-root /tmp \
    --i-understand /tmp/copy.img
```

`make fixtures` regenerates the fixture from a seed rather than shipping a 256 MB binary,
and refuses to overwrite the committed digests unless `--no-check-expected` is passed.

### The frontend

Two self-contained pages, in this repository, built to the **AURUM** standard (Black
Titanium finish). No build step, no framework, no bundler, and **no network request of any
kind at runtime** — the demo machine is air-gapped and this is deliberate.

```sh
make ui        # run the engine, rebuild both pages from THAT run, open them
make ui-check  # token-drift + payload freshness, without running the engine
make ui-serve  # http://localhost:8787 if a browser policy blocks file://
```

[`ui/approach.html`](ui/approach.html) — eight scroll-scrubbed scenes making one argument:
every tool asserts, this one proves. [`ui/instrument.html`](ui/instrument.html) — the tool
itself: target pre-flight, live sector telemetry, the timing verdict with its arithmetic,
and all 56 carve candidates with their four confidence terms broken out.

**They are an output of the engine, not a picture of it.** `make ui` carves the image,
wipes a copy, carves again with identical parameters, regenerates `ui/payload.json` from
those artifacts and re-inlines it into both pages. The wipe never targets `out/fixture.img`
— it runs against a copy under `out/ui-run` with `--allow-root` pointed there, so the
guard's containment check is what prevents a mistake rather than the script's good
intentions, and the fixture's SHA-256 is re-verified afterwards.

Because the pages are self-contained, the payload and the token layer are **copies**, and a
copy nobody regenerates goes stale silently. `ui/inline.py` is therefore both the
regeneration step and a drift detector: it checks all **86 primitives** in every page
against [`ui/tokens.css`](ui/tokens.css) and exits 4 naming the token if one differs. A page
whose gold is one digit off from the standard is exactly the defect nobody catches by eye.

### Tests

```sh
make test                              # cargo test --release + pytest
```

485 cargo tests passed, 0 failed, 4 ignored. 260 pytest passed.

By scope: carve lib 252 · carve bin 19 · carve integration 5 + 12 · device lib 42 ·
wipe lib 145 · wipe bin 10. Python: fixtures, guard, guard-conformance vectors, carve
recall, wipe residue, module declarations.

---

## Safety

This software destroys data. Every write goes through a guard that **defaults to deny**.

- Containment is decided by **inode ancestry** — walking the resolved path upward comparing
  `(st_dev, st_ino)` against the allowed roots — never by string prefix, because macOS
  firmlinks give one directory two resolved paths and case-insensitive filesystems give one
  file two spellings.
- Device targets are refused unconditionally on macOS; on Linux they need three further
  independent factors AND-ed, with an allowlist that is empty by default.
- The typed confirmation is evaluated **last**, as a trailing conjunct that grants nothing
  on its own, so a refused target never reaches it and no operator learns that typing harder
  gets them through.
- The policy is exercised by a shared conformance table — **85 target rows + 21
  policy-construction rows** — run by a Rust test *and* a Python test, so the two
  implementations cannot drift apart silently.

A racing harness that flips an allowed root to a symlink is part of the suite in both
languages. It exists because it found a real defect: `O_TRUNC` once sat in the same syscall
that established a file's identity, so the kernel zeroed a victim **before** the identity
check could refuse it. Fixed, and re-verified over 81,815 iterations with the out-of-root
victim byte-unchanged.

---

## Limitations, stated rather than discovered

CLAUDE.md rule 1: the tool never claims more than it verified.

- **Sampled read-back covers 0.1953% of the medium** (1,024 of 524,288 sectors). The outcome
  code says so — `OVERWRITE_VERIFIED_ON_SAMPLE`, `whole_medium_claim: false`. The largest run
  of consecutive sectors the sampling plan never touches is **2,815 sectors, 0.5369% of the
  medium**; a region left unwiped inside it would pass a sampled verdict. `--verify
  exhaustive` closes it, and a regression test proves both halves.
- **28 of 40 is demonstrated recall; 33 of 40 is the reachability ceiling.** Two different
  numbers that never share a sentence. Of the twelve not recovered: five plaintext files
  carry no signature, five need fragment reassembly, two were fragmented deliberately to
  defeat this engine.
- **A confidence score says "this is a well-formed object of this type." It does not say
  "these are the original bytes."** For PNG, GZIP and ZIP, which carry CRCs over their
  payload, those claims nearly coincide. For JPEG entropy-coded data and MP4 sample data
  there is no such check and they diverge — `handover_briefing.mov` is admitted at 0.9000
  with a perfect structural score, a length matching the planted file to the byte, and a
  different SHA-256.
- **One fragmented file is unrecoverable by any carver, not just ours.** QuickTime's `mdat`
  declares its own length in the first fragment, so any tail of the right length tiles
  perfectly and the format carries no checksum over sample data: 6,660 splices accept,
  exactly one is correct, and no byte distinguishes them.
- **The behavioural audit rules out one specific lie** — a firmware command returning success
  without doing the work — independently of anything the firmware says. It does not prove an
  erase happened when timing looks plausible: a device that fakes host writes fast enough
  would inflate the measured baseline and disarm it. Only read-back addresses that.
- **Everything here is measured on loopback images on one laptop.** No real ATA or NVMe
  device has been timed, and no real drive has been erased.

---

## Layout

```
core/          Rust workspace
  device/        Device trait · ImageFile · LinuxBlock (gated) · Windows stub · the write guard
  carve/         signature scan · 7 structure validators · confidence · bifragment reassembly
  wipe/          overwrite passes · sampled verification · behavioural audit · telemetry
  verify/        Phase 4 — the adversarial loop
  ledger/        Phase 4 — Merkle chain + Ed25519
fixtures/      deterministic image builder, corpus generator, the write guard, conformance vectors
docs/          architecture (D1–D6) · output schema · TSK cross-check · standards · demo script · evidence
ui/            the instrument, one self-contained file
tests/         pytest: fixtures, guard, vectors, recall, residue, module declarations
```

`docs/ai-log/` records what was asked, what was produced, and what was wrong — including the
findings that changed the design. It is kept because a team that can name its own failure
modes is more credible than one that claims none.
