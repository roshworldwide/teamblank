# Architecture

Component map, the telemetry path from Rust to the instrument, and the published
confidence function are written at Phase 2, against measured output only. This file
opens with the decisions that constrain everything downstream.

## D1 · Fixture substrate — hand-written FAT32, stdlib Python only

**Decided 2026-09-02. Status: adopted.**

The fixture is a FAT32 image this project writes byte by byte in pure Python. No
container runtime, no kernel formatter, no mounting, no new dependency.

### Why not the kernel toolchain

The build pack assumed Linux. This machine has no `losetup`, no `mke2fs`, no
`mkfs.vfat`, and a Docker daemon that is down. Two paths out were investigated and
both were rejected on measurement, not preference.

*Docker.* Docker Desktop 4.81.0 is installed but client-only: `docker info` exits 1,
`AutoStart` is false, and a 2.1 GB half-applied 4.86.0 update has been staged since
2026-08-12 that the next launch resumes. The tooling actually needed is 4.73 MiB; the
runtime around it is 17.2 GB, an 8 GB VM on a 16 GB machine, and root LaunchDaemons
wanting an admin password on a fresh laptop. No fallback runtime exists — colima,
podman, lima, nerdctl and qemu are all absent. `demo_script.md` already forbids this
shape in writing: a live filesystem operation never stands between the team and a
working demo.

*Native builds.* `mke2fs`, `debugfs`, `dumpe2fs` and `e2fsck` do build on macOS arm64,
and dosfstools 4.2 builds with a two-line shim. This was the strongest form of the
ext4 argument and it still fails, for one reason: the resulting image was validated
only by `dumpe2fs` — the same tool family inspecting its own output. No Linux kernel
has ever mounted it. The realism credential does not exist in any form available to
this team, while the cost of a second substrate is fully real.

Measured against determinism, the comparison is not close. `mke2fs -d` imports host
uid, gid and umask with no suppressing flag (umask 022 and 077 produce different
image hashes), one changed line in `mke2fs.conf` moves the hash, and three plausible
base tags carry three different e2fsprogs versions. `SOURCE_DATE_EPOCH` is not
honoured by released dosfstools 4.2. Meanwhile the pure-Python image reproduced
byte-identically across three independent runs under varied `TZ`, `LANG`, `umask`,
working directory and `PYTHONHASHSEED`, and across three CPython builds with three
different SQLite versions.

### Why a hand-written filesystem is not a shortcut

The carver does signature and structure carving and never parses filesystem metadata.
The substrate therefore has exactly three jobs: place bytes at known offsets, fragment
them across non-contiguous extents, and support deletion as unreferenced data. A
chosen cluster chain does all three better than a requested one — it is the only
approach where the fragment layout is an input the writer obeys rather than an
allocator outcome discovered afterwards. That is what makes the tri-fragment and
out-of-order cases buildable at all. `mke2fs` cannot be asked for them.

Evidence the image is a real filesystem and not a plausible-looking one: Apple's
`msdos` driver mounts it read-write, `fsck_msdos` exits 0 with no orphan clusters, and
a negative control confirms the driver is genuinely walking our chains — rewriting one
mid-chain FAT entry makes the fragmented file vanish from the mount. Five single-field
boot-sector corruptions each produced `no mountable file systems`, so the test can fail.

### The reproducibility defect this uncovered

`zlib.compress` output is a property of the linked libz, not of the input. Info-ZIP and
zlib produced 13,937 and 14,066 bytes from identical input, both decompressing
correctly. PNG, DOCX and GZIP all ride on DEFLATE, so the corpus would have differed
per laptop and the reproducibility rule would have failed in a way no single-machine
test could detect. uv's managed CPython bundles SQLite statically but still links the
system libz, so pinning the interpreter does not pin zlib.

The fixture therefore carries its own fixed-Huffman DEFLATE encoder. `zlib` is used
only for CRC32, Adler32 and round-trip verification, which are fixed algorithms.

### Nothing is mounted, by decision

`losetup` is inherited Linux shape from the build pack, and `hdiutil attach` is worse
than unnecessary on macOS: it assigns a runtime `/dev/diskN` that no allowlist written
in advance can name, and mounting into `/Volumes` lets Spotlight and `fseventsd` write
into the fixture. The carve/wipe/carve loop was run end to end on a raw image file with
zero subprocesses and zero mounts. `Loopback images only` in CLAUDE.md is read as scope
— image files rather than block devices — not as an instruction to attach anything.

The consequence, stated plainly: no kernel validates the image at build time, so this
is described as a raw image carrying FAT32-structured metadata, which is all the carver
requires, and never as a certified FAT32 volume.

### What this costs, and where it is written down

The fixture is FAT32 and nothing else. ext4, NTFS and APFS are out until nationals and
go on the slide rather than into the build. Byte-identity across six laptops remains an
inference until one teammate clones, builds and diffs a hash; no slide claims it before
then. The full limitations list is maintained in `standards_map.md`, and every one of
them is reproduced in the certificate rather than summarised.

### Operator decisions taken

- The demo reports the **measured** recovery count with both deliberately unsolvable
  cases named on screen, not a round 40 of 40. The fixture plants a tri-fragment DOCX
  and an out-of-order JPEG that bifragment gap carving cannot solve by construction; a
  fixture containing only cases we pass is not evidence.
- The writer implements **VFAT long filenames**, so `fls` output shows real names during
  the independent cross-check rather than 8.3 stubs.
- **The Sleuth Kit is installed** as the independent carving cross-check named in the
  locked stack. It is development tooling only: never imported at runtime, never added
  to `pyproject.toml`, and the cross-check test skips when it is absent.

## D2 · The confidence function, and the margin that actually protects it

**Measured 2026-09-03 through shipped `structure::validate` and `confidence::confidence`.
Reproduced by an independent checker on its own Python and Rust path. Enforced in CI by
`core/carve/tests/residue_separation.rs`.**

### The published formula

```
confidence = 0.40 * signature_integrity
           + 0.35 * structural_validity
           + 0.15 * entropy_consistency
           + 0.10 * size_plausibility
```

Every term is in [0,1], computed, and independently unit tested. The UI renders all four as a
stacked bar, because a score whose derivation is not on screen is a score a jury will not believe.

### What separates a real file from a decoy

Free space in the fixture carries 21 deliberate decoys — 8 bare JPEG headers and 13 bare GZIP
headers, counted in the manifest.

```
35 planted, carvable   min 0.9000   max 1.0000   mean 0.9571
21 residue decoys      min 0.5186   max 0.6500   mean 0.5805
lowest true positive 0.9000 | highest false positive 0.6500 | gap 0.2500 | zero overlap
```

Per-term weighted contribution to that separation:

| term | weight | contribution |
|---|---|---|
| signature_integrity | 0.40 | +0.0190 — *not separation, see below* |
| structural_validity | 0.35 | **+0.3458** |
| entropy_consistency | 0.15 | +0.0118 |
| size_plausibility | 0.10 | +0.0000 |

**Structure supplies more than the entire gap.** Size supplies exactly nothing — every decoy
scores full marks on it. And signature integrity supplies nothing either: all 8 residue JPEGs
resolve a valid `FF D9` footer in sequence and score a perfect 1.0000, identical to all 5 planted
JPEGs. At the signature layer a noise blob and a photograph are indistinguishable. That is the
empirical answer to *"why not just match magic bytes?"* — and it is why the 0.35 weight is where
it is.

Term 1's apparent +0.0190 is a kind-mix artefact, not discrimination: the residue population is
62% footerless GZIP against 43% of the planted population. Within every kind, signature integrity
awards a decoy exactly what it awards the real file. The CI test asserts that per-kind equality so
the figure cannot be misread as separation later.

### Three margins, and only one of them binds

The admission gate is `confidence::MIN_CONFIDENCE` = 0.75. It is not 0.90, because GZIP, MP4 and
SQLite define no terminator, so term 1 caps at 0.75 for them and a byte-perfect object of those
kinds tops out at exactly 0.9000. The fixture plants 15 such files; a 0.90 gate would discard all
15 to buy nothing against a highest false positive of 0.6500.

| | value | what it means |
|---|---|---|
| population gap | 0.2500 | distance between the two distributions |
| gate headroom | 0.1000 | decoy ceiling 0.6500 up to the 0.75 gate |
| **structural-credit headroom** | **0.0357** | **the one that has to hold** |

A decoy already scoring full marks on signature, entropy and size — which all 8 residue JPEGs
do — carries 0.6500 for free. It clears the gate as soon as structural credit reaches

```
STRUCTURAL_BREACH_POINT = (MIN_CONFIDENCE - NON_STRUCTURE_CEILING) / W_STRUCTURE
                        = (0.7500 - 0.6500) / 0.3500
                        = 0.285714
```

The worst decoy today scores 0.2500 of structural credit. **The real margin is 0.0357**, and it is
the number to quote — not the 0.2500 population gap, which describes a distance nothing enforces.
Earlier figures of 0.4700 headroom, a 0.72 breach and a 0.9020 worst case were all computed against
the retired 0.90 gate and are wrong.

The breach point is derived in code from the weights and the gate, never hardcoded, so it moves if
they do. Confirmed by mutation: forcing residue structural credit to 0.28 leaves the guard green,
0.29 turns it red, and 0.30 admits four JPEG decoys at 0.7550. One residue GZIP already earns
0.2500 of genuine partial credit — its header parses cleanly and only the DEFLATE stream fails — so
this is a live margin, not a theoretical one.

### Known limits of this measurement

- Measured on one fixture. It contains no PNG, PDF, ZIP, SQLite or MP4 decoys, so false-positive
  behaviour on those five kinds is unmeasured.
- The residue span for footerless decoys is a policy choice. Only the adversarial ceiling of
  0.6500 — entropy and size pinned to 1.0 for every decoy — is safe to quote against a challenge
  to that choice.
- This measures what `confidence()` says about a correctly recovered object. It is not a recall
  claim, and it says nothing about what `bifragment.rs` can reassemble.

## D3 · Demonstrated recall, and the cross-check against The Sleuth Kit

**Measured 2026-09-03 against `out/fixture.img` through `core/target/release/carve`.
Re-derived independently by an adversarial verifier joining on SHA-256. Full comparison in
[tsk_crosscheck.md](tsk_crosscheck.md).**

### Two numbers that are never the same sentence

| | value | meaning |
|---|---|---|
| reachability ceiling | 33 of 40 | what this fixture makes reachable in principle: 28 contiguous + 5 needing reassembly |
| **demonstrated recall** | **28 of 40** | what the contiguous engine measurably recovered, byte-exact |

`bifragment.rs` is deliberately deferred, so the engine handles contiguous objects only and
recovered 28 of the 28 contiguous-reachable files — zero shortfall, nothing lowered to reach it.
The twelve it did not recover each carry a stated reason: five plaintext files carry no signature,
five are stored in non-contiguous fragments, and two were fragmented deliberately to defeat it.

### Admitted is not recovered

The engine admits 33 objects above the 0.7500 gate; 28 are byte-exact against ground truth. Of the
other five, four are the leading fragment of a file stored in pieces — real data, correctly
identified, incompletely assembled. The fifth, a ZIP at offset 1,228,603, is a genuine false
positive and scores **0.7550**: barely over the gate, the lowest admitted score in the run.

That distinction only exists because we planted the corpus and know the answer. In the field a
carver cannot tell the two apart, which is exactly why the confidence score has to be published
per object rather than summarised into a count. `MP4@65943552` is the case that proves it: its
length is `handover_briefing.mov`'s planted size to the byte and its structural validity is
1.0000, yet the digest differs. A row count or an offset match calls that a recovery. Only the
hash rejects it.

### Both tools recover 28 of 40, and they are not the same 28

| | count | which |
|---|---|---|
| both byte-exact | 21 | live, contiguous, signature-bearing |
| TSK only | 7 | 4 live plaintext + 3 live fragmented |
| carver only | 7 | the deleted, contiguous, signature-bearing set |
| neither | 5 | 1 deleted plaintext + 4 deleted fragmented |
| **union** | **35 of 40** | |

Zero rows disagree on content: wherever both tools produced bytes for the same file, the digests
match each other and the manifest.

The mechanism behind the split is the whole argument. TSK's `icat` reads live files **through
directory metadata** — filesystem parsing, not carving. The 12 deleted files are metadata-stripped
by design (`first_cluster` and `size` both zeroed, confirmed by `istat` and a raw directory
parse), so that path returns nothing for them: `tsk_recover` over unallocated space reports
**"Files Recovered: 0"**. Our carver, over that same 263,948,288-byte `blkls` stream, recovers
**7 byte-exact**. TSK 4.15.0 ships no file carver at all.

Our signature scanner is itself validated against TSK: a byte-granular `sigfind` sweep over all
512 intra-sector offsets returns 19 JPEG and 18 GZIP hits, and `carve --no-dedup` emits the
identical offset lists, element for element, set difference empty in both directions.

### Where we are worse, stated plainly

On a live filesystem with intact metadata, TSK is the better tool. It reads the four live
plaintext files out of their directory entries in microseconds; a signature carver cannot see a
file that has no signature, and returns nothing. It also recovers three live fragmented files we
currently cannot. The deficit is structural, not a tuning gap.

The fifth plaintext file is deleted, and there neither tool recovers anything: no metadata for TSK
to follow, no signature for us to find.

### Cost

`fls` 0.076 s · `tsk_recover -a` 0.070 s · `blkls` 0.309 s · `carve` whole image 1.655 s over
268,435,456 bytes.

## D4 · Bifragment gap carving — what it recovers, and what no validator can

**Measured 2026-09-03. Two adversarial verifiers re-derived these figures independently, one
building its own measurement crate against the public API. Off by default.**

### The numbers

| | contiguous engine | with `--reassemble` |
|---|---|---|
| demonstrated recall | 28 of 40 | **30 of 40** |
| wall clock, 256 MiB | 1.65 s | 66.4 s |
| structure validations | — | 2,014,323 across 63 searches |

Reassembly recovers `entropy_heatmap.png` (gap 1 cluster, 4,485 validations) and
`imaging_transcript.txt.gz` (gap 16 clusters, 4,245 validations). Both carved extent lists equal
the manifest's element for element.

**The ≥60% fragmented-recall bar is not met: 2 of 5 is 40%.** The bar was not lowered and the
figure is not rounded. Each of the three failures has a different cause and only one of them is
ours to fix.

### The search

A bounded 2-D lattice over split point and gap, both quantised to the cluster grid: 256 × 128 =
32,768 cells on this fixture. The gap bound is inclusive and agrees with the manifest's
`max_gap_is_inclusive`, which is observable rather than academic because
`disposal_certificate.pdf` sits exactly on it — an exclusive bound would lose the splice.
Searching on cluster boundaries rather than bytes reduces the lattice by exactly cluster² =
4,194,304×.

### The three that did not reassemble

**`disposal_certificate.pdf` — a validator gap, fixable.** Not the bound: the manifest's own
splice is inside the lattice and is accepted. `structure::pdf` resolves `startxref` and verifies
34 of 34 xref offsets without ever decoding a stream body, so a ~21 kB FlateDecode payload goes
unread and ten different splices all validate. Ten accept, one is content-correct, none is
determined.

**`sealing_procedure.mov` — a limit of the format, not of this implementation.** `mdat` declares
its own length inside the first fragment, so the object's total length is fixed by the head and
*any* tail of the right length tiles perfectly. QuickTime carries no checksum over sample data.
6,660 splices accept, exactly one is correct, and **no byte in the format distinguishes them.** No
structure validator can separate these, ours or anyone's.

**`handover_briefing.mov` — never searched, correctly.** `structure::mp4` accepts the contiguous
read: right length to the byte, wrong bytes. The precondition declines to search an object that
already validates in place, which is the right rule and here costs a recovery.

### The two planted failures, and why they fail

`media_inventory.docx` (3 fragments) and `evidence_bag_seal.jpg` (reversed, gap −77 clusters) are
not recovered. The docx exhausts all 32,768 cells with zero accepting splices.

One attribution was corrected under challenge. The reversed JPEG's non-recovery is
**over-determined**: re-planting its true bytes *forward* in benign filler recovers 0 of 24
split × gap layouts, while PNG and GZIP objects of the same shape through the same harness recover
24 of 24. So reversal is *sufficient* to explain the failure but was not shown to be *necessary* —
the operative cause is determinacy, because JPEG carries no checksum over entropy-coded data. The
tri-fragment claim is the demonstrable one: a real 63,749-byte OOXML file laid out forward is
recovered byte-exact at two fragments in 65 validations and refused at three, so the refusal is a
property of the fragment count, not of the kind.

### False positives under reassembly

The margin did not move. Across 1,867,833 residue assemblies the shipped validator accepted
**zero**, so the refusal rests on outright rejection rather than on a heuristic. Worst residue
structural credit is 0.250000 against a breach point of 0.285714 — headroom 0.035714, unchanged.

Two guards were added after a verifier fabricated an object the engine admitted at confidence
1.0000. Writing one real 2 KiB JPEG header prefix onto free space produced admitted reassembled
records at a rate of **13 in 100** cluster-aligned offsets. Determinacy now requires a genuine
contradiction on the shrink side rather than counting an unspliceable neighbour as a pass, and a
second extent below one cluster is not stated as an object. That took the rate to **2 in 100**,
and cost no recovery.

**The residual is published, not closed.** Two offsets still fabricate, both splicing the same
59,927-byte tail, structural 0.8000, total 0.9300. The cause is in `structure/jpeg.rs`: a
length-bearing marker inside the entropy-coded scan is treated as an anomaly to report rather than
a fatal error, so a scan can step over residue until it lands on an `FF D9`. Making it fatal is the
real fix and it belongs to the contiguous validator, where it would change already-published
numbers — so it is stated here rather than patched quietly.

### A correction to an earlier figure

Earlier build reports quoted 0.300000 as the worst rejected-assembly structural credit. That was
the residue population with the planted files filtered out, and it understated the image by 3.2×.
Measured over the plants as well: `media_inventory.docx` reaches 0.957143 and `entropy_heatmap.png`
reaches 0.989286 one cluster off its true splice, with 27 of 28 chunk CRCs verifying. Scored, those
would be admitted at 0.9850 and 0.9963. Both are rejected today by the validator's hard gate, and
both are now asserted as named constants so the figures cannot drift unnoticed.

## D5 · The behavioural timing audit — catching a sanitize that did nothing

**Measured 2026-09-03. Raw captured run at [evidence/fake_sanitize_run.txt](evidence/fake_sanitize_run.txt),
with commit, timestamp and the full JSON report.**

Drives lie. A firmware sanitize command can return success without doing any work, and the return
code is indistinguishable from an honest one. This project never trusts it —
`return_code_trusted` is `false` in every artifact the engine emits.

### The result

A simulated `ATA SANITIZE BLOCK ERASE` claiming 268,435,456 bytes:

| | |
|---|---|
| verdict | **`UNVERIFIED_TIMING`** |
| device reported success | `true` |
| measured elapsed | **1,000 ns** |
| expected minimum | **431,059,458 ns** (0.431 s) |
| ratio | 2e-06 — the command returned **431,059× faster than physically possible** |
| threshold | 0.05 |

### The floor is derived, never hardcoded

The first question a technical jury asks is where 431 ms comes from, and the answer cannot be a
constant — a fixed floor false-positives on fast NVMe and the demo dies on stage.

```
expected_min_ns = work_bytes × probe_elapsed_ns ÷ probe_bytes
                = 268,435,456 × 431,059,458 ÷ 268,435,456
                = 431,059,458 ns
```

computed in `u128` integer arithmetic, truncating downward so rounding always favours the device.
The baseline is a *measured* write rate — 622,734,175 B/s on this run, sourced either from a
32 MiB calibration probe written before pass 1, or from the observed overwrite pass itself when
one has run. Every artifact publishes all three numbers side by side — measured rate, derived
floor, observed elapsed — plus `baseline.source`, `probe_bytes` and `probe_elapsed_ns`, so a
reader can redo the division without trusting our ratio.

### A second, independent witness

Timing is not the only signal. The medium is sampled before and after the command:

```
medium_witness_before  c82e10f39199bc4fb1728f8bf12f3049717809b47956437d3f549917b57fc9c6
medium_witness_after   c82e10f39199bc4fb1728f8bf12f3049717809b47956437d3f549917b57fc9c6
medium_unchanged       true          (256 sampled sectors)
```

So the claim is corroborated twice: the command was impossibly fast **and** the bytes it claimed
to erase are unchanged. The disposition is recorded as `NOT_A_SANITIZATION_CLAIM`.

### Reproducibility — approximate, and this constrains rule 6

Two independent runs:

| | run A | run B |
|---|---|---|
| measured elapsed | 1,167 ns | 1,000 ns |
| expected minimum | 421,794,458 ns | 431,059,458 ns |
| ratio | 3e-06 | 2e-06 |
| verdict | `UNVERIFIED_TIMING` | `UNVERIFIED_TIMING` |

**The verdict reproduces exactly; the figures reproduce only approximately.** That is inherent —
both numbers are real measurements of a real machine, and a baseline that did not move between
runs would mean it was not being measured.

This has a consequence, and it is now a **resolved decision** rather than an open one.

CLAUDE.md rule 6 originally required `make demo` to produce byte-identical certificates. Timing
figures cannot be byte-identical, so something had to give. The tempting fix — exclude timing from
the reproducibility hash — was rejected, and the reason is worth stating plainly: **the timing
verdict is the single field most worth forging.** It is the evidence that the drive lied. A section
left outside the hash is a section an attacker can rewrite, and putting the most attackable field
there would have been exactly backwards.

**The resolution: sign everything, reproduce a declared subset.** The certificate carries two named
regions and both sit inside the Ed25519 signature and the Merkle chain.

| region | contents | asserted byte-identical |
|---|---|---|
| `deterministic_core` | run id, target, method, `medium_witness_before` / `_after`, `medium_unchanged`, verdicts, pass/fail | **yes** |
| `measurement_envelope` | measured rate, derived floor, observed elapsed, `baseline.source`, `probe_bytes`, `probe_elapsed_ns` | no — signed, not reproduced |

Only `deterministic_core` carries the reproducibility assertion, and the certificate states on its
face which fields that assertion covers, so a reader is never left inferring it. Rule 6 now reads:
byte-identical `deterministic_core` from a fresh clone; signature validity over the whole
certificate.

Note what this preserves. The verdict itself — `UNVERIFIED_TIMING` — and both medium witnesses live
in `deterministic_core`, so the *finding* is reproducible even though the *stopwatch* is not. A
tamperer who edits the measured elapsed to make a fake sanitize look plausible breaks the
signature; a tamperer who edits the verdict breaks both the signature and the reproducibility
assertion. This must be settled before the certificate format is frozen in Phase 4, and it now is.

### What this proves, and what it does not

It rules out the specific failure where a firmware command returns success without doing the work,
independently of anything the firmware says. It does **not** prove an erase happened when timing
looks plausible: a device that fakes host writes fast enough would inflate the measured baseline,
shrink the expected minimum, and disarm the audit. Only read-back verification addresses that, and
it is a separate and necessary check.

Every figure here is host file I/O on one laptop. No real ATA or NVMe device has ever been timed.

## D6 · 28, 30 and 33 reconciled — and what a confidence score can actually mean

**Measured 2026-09-03. The demo number is 28. It is not a range.**

### The three figures are not three measurements of one thing

| figure | what it is |
|---|---|
| **33 of 40** | reachability ceiling — what this fixture makes reachable in principle: 28 contiguous + 5 needing reassembly |
| **30 of 40** | demonstrated recall with `--reassemble`, 66.4 s |
| **28 of 40** | demonstrated recall on the DEFAULT path, 1.65 s — **this is the demo number** |

28 and 30 are the same binary at different flags, not a disagreement. `--reassemble` is off by
default because it costs 40× for two files and cannot fit a 90-second demo. The only difference
between the two runs is that flag; it recovers exactly `entropy_heatmap.png` (1-cluster gap) and
`imaging_transcript.txt.gz` (16-cluster gap).

### The three reachable files we do not recover

| path | kind | offset | outcome | signature / structure / entropy / size |
|---|---|---|---|---|
| `disposal_certificate.pdf` | PDF | 170,430,464 | rejected at 0.7200 | 1.00 / **0.20** / 1.00 / 1.00 |
| `sealing_procedure.mov` | MP4 | 65,796,096 | no record emitted | not scored |
| `handover_briefing.mov` | MP4 | 65,943,552 | **admitted at 0.9000** | 0.75 / **1.00** / 1.00 / 1.00 |

**All three are stated limitations, not defects to fix. Each for a different reason.**

**The PDF is validator incompleteness with a known fix.** `structure::pdf` resolves `startxref` and
verifies 34 of 34 xref offsets without ever decoding a stream body, so ten different splices all
validate and none is determined. The engine falls back to a contiguous span of 308,199 bytes
against a true 46,056 — 6.7× too long — which scores 0.20 structurally and is correctly rejected.
Adding per-stream inflate with an Adler-32 check would very likely determine the correct splice.
It is not being done now because it changes what the *contiguous* validator accepts, and those
numbers are already published. Queued, named, and costed rather than quietly carried.

**The first MP4 is a limit of the format.** `mdat` declares its own length inside fragment 1, so
the object's total length is fixed by the head and any tail of the right length tiles perfectly.
QuickTime carries no checksum over sample data. 6,660 splices accept, exactly one is correct, and
no byte in the format distinguishes them. No structure validator can separate these — ours or
anyone's. The engine correctly emits nothing rather than guessing.

**The second MP4 is the important one, and it is a limit on what confidence means.**
`handover_briefing.mov` is *admitted* at 0.9000 with a perfect 1.00 structural score, a length of
66,689 bytes matching the planted file exactly, and a different SHA-256. No term fell short. The
formula did precisely what it claims and was still wrong.

The reason generalises, so it belongs on the slide rather than in a footnote:

> **A confidence score says "this is a well-formed object of this type." It does not say
> "these are the original bytes."** For formats carrying internal integrity checks — PNG chunk
> CRCs, GZIP CRC32 and ISIZE, ZIP per-entry CRCs — those two claims nearly coincide. For formats
> carrying none over their payload — JPEG entropy-coded scan data, MP4 sample data — they can
> diverge completely, and no weighting of signature, structure, entropy and size can close the
> gap, because none of those four terms has anything to check the payload against.

This is why the fixture exists and why recovery is joined to ground truth by SHA-256 rather than by
row count. In the field there is no manifest to join against, which is exactly why the per-object
score is published with its four terms visible instead of collapsed into a count of recoveries.
`handover_briefing.mov` is the case that proves a row count would have lied.

## D7 · Windows as a development platform — one API, two guards, one of them weaker

**Implemented 2026-09-03. Verified on Windows 11 26200, rustc 1.97.1, CPython 3.10.
484 cargo tests and the full pytest suite pass there.**

The workspace did not compile on Windows at all. `core/device/src/guard.rs` carried
`#![cfg(unix)]` while `lib.rs` named `guard::Policy` unconditionally, so `device` failed
with 13 errors and `wipe` failed behind it. Two of six teammates are on Windows; for them
rust-analyzer was red across the whole workspace and no test could run.

### What was done

The guard is now a directory with one backend per platform and a selector, in both
languages. The POSIX files are byte-for-byte what they were — `core/device/src/guard.rs`
moved to `guard/unix.rs` and `fixtures/guard.py` to `fixtures/guard/posix.py` with no
edit but the removal of the `cfg` attribute — so `fixtures/guard_vectors.json`, the
cross-language conformance table, still measures exactly the code it was measured
against.

### The two backends do not guarantee the same thing

| | POSIX | Windows |
|---|---|---|
| containment | `(st_dev, st_ino)` identity walk | **same** (Python) / canonicalised components (Rust) |
| link refusal | `O_NOFOLLOW` on every component | reparse-point check per component |
| descent | `openat` from the root, re-checked on the fd | resolve, open, re-check on the handle |
| **TOCTOU** | **hardened** | **not hardened** |
| device targets | gated, allowlisted, arming required | **always refused** |
| `DENY_MULTIPLE_HARDLINKS` | enforced | **unreachable** — `st_nlink` is always 1 there |

The TOCTOU row is the real difference and it is not softened anywhere. `os.supports_dir_fd`
is empty on Windows and there is no `O_NOFOLLOW`; the Rust identity primitives that would
substitute — `volume_serial_number`, `file_index` — are behind the unstable
`windows_by_handle` feature, which a zero-dependency crate cannot use. So the Windows
backend cannot prove the path it checked is the path it opened. It re-checks on the open
handle, which narrows the window and does not close it.

**Every allow the Windows backend issues carries that sentence in its own `detail`**, so an
operator reading an audit line never has to know which platform produced it to know what it
is worth. Rule 1 says the tool never claims more than it verified; a guard that quietly
implied the POSIX guarantee on Windows would be exactly that claim.

Nothing about the Windows backend widens the allowed set. It refuses device and verbatim
namespaces outright, refuses reserved DOS device names — `out\NUL.img` is a device, in every
directory and at any extension — and refuses to build a policy that arms devices at all.

### One rule that had to be inverted, and why

The POSIX guard refuses a root that **is** a system directory or **contains** one. The first
Windows draft also refused any root **under** one, and that refused the repository: on
Windows every checkout lives under `C:\Users\<name>`, because there is no `/home`. A guard
that makes itself unusable protects nothing. So `FORBIDDEN_UNDER` is `FORBIDDEN_TOP` minus
`USERS`, and `C:\Users` as a root, and the operator's own profile directory as a root, are
both still refused. This is the one place the two platforms' rules genuinely differ in shape
rather than in strength, and it is named here rather than left in a constant.

### Reproducibility, now demonstrated on two operating systems

`fixtures/build_image.py` runs on Windows and produces image sha256
`d85612b255ff8e72e1ab8d7a34c227b67c3cb3acda75e2a92e5042758ac2df41` and manifest sha256
`1808494ecc3cd5e21d0d9790af5478cda6aa7011b531e20ea1655e3edbc2cd69` — identical to the
committed record captured on macOS, under a CRLF working tree. Rule 6 previously rested on
three runs on one laptop; the cross-platform half of it is no longer an inference.

### Two portability defects this uncovered, both real

- **`carve` could leak a host path into a report.** `relative_label` tested
  `Path::is_absolute`, which on Windows requires a drive prefix, so a POSIX path such as
  `/private/var/tmp/fixture.img` reported *relative* and was copied into `run.image_path`
  whole. The predicate is now "has a root component or a prefix", which catches both
  spellings on both platforms.
- **`ImageFile` misnamed the cause for a directory.** It opened first and checked
  `is_file()` after, but Windows will not open a directory at all, so the caller was told
  `DEVICE_IO` "access denied" — a permission failure that never happened. It now classifies
  before opening, and both platforms name the same cause.

### What is not claimed

No Windows block device has ever been touched, because none can be. The Windows guard has
no race-freedom property and no test pretends to cover one. `DENY_MULTIPLE_HARDLINKS` is
published and unreachable there, so a hard link from outside an allowlisted root into it is
**not** detected on Windows. Coverage is `tests/test_guard_windows.py` and the unit tests in
`core/device/src/guard/windows.rs`; the POSIX suites skip on Windows and say what they are
not covering rather than reporting green.
