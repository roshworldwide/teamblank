# The Sleuth Kit cross-check

**Measured 2026-09-03. The Sleuth Kit 4.15.0, macOS 26.6.2, arm64.**
Subject: `out/fixture.img`, 268435456 bytes,
sha256 `d85612b255ff8e72e1ab8d7a34c227b67c3cb3acda75e2a92e5042758ac2df41`.
Ground truth: `out/fixture.manifest.json`,
sha256 `1808494ecc3cd5e21d0d9790af5478cda6aa7011b531e20ea1655e3edbc2cd69`.
Nothing was mounted. TSK read the image file; the carver read the same image file.

CLAUDE.md's locked stack names TSK "for cross-check only". This file is that cross-check,
run file by file and compared by SHA-256, never by row count. Every figure below has the
command that produced it printed beside it. The carver under test is
`core/target/release/carve`, built by `cargo test --release -p sentinelwipe-carve`
(237 + 15 + 5 + 12 tests pass, 0 failed, 2 ignored).

---

## 0 · The one distinction the rest of the document rests on

TSK and this project are not doing the same job, and the comparison is worthless unless
that is said first.

| | reads | answers the question |
|---|---|---|
| `fls`, `icat`, `istat`, `tsk_recover`, `sorter` | directory entries and the FAT | *what does the filesystem say is here?* |
| `blkls` | the unallocated cluster stream | *give me the bytes the filesystem no longer claims* |
| `sigfind` | every sector, at one fixed intra-sector offset | *where does this byte pattern occur?* |
| `core/carve` | every byte of the image | *what object is here, and how sure am I?* |

`icat` is **filesystem parsing, not carving**. It follows a cluster chain that the
directory entry hands it. Where the entry survives, `icat` is exact and effortless and
beats a carver outright. Where the entry is gone, `icat` has nothing to follow.

The fixture's 12 deleted files are metadata-stripped by design, so they are the only part
of this image where a carving comparison is possible at all. Section 1 reports the metadata path and
section 3 reports the carving path; section 2 puts both beside the carver's whole-image
run. They are labelled apart on purpose and never summed into one figure.

---

## 1 · The metadata path — what TSK sees through the filesystem

### 1.1 · `fls` sees all 40, and flags 12 as deleted

```
$ fls -r -p out/fixture.img
r/r 3:	SENTINELWP  (Volume Label Entry)
r/r * 7:	evidence_log_2026-01-14.txt
r/r 11:	interview_transcript_raw.txt
...
r/r * 125:	handover_briefing.mov
v/v 8355459:	$MBR
v/v 8355460:	$FAT1
v/v 8355461:	$FAT2
V/V 8355462:	$OrphanFiles
```

41 `r/r` rows — one volume label and the 40 planted files — plus four `v/v`/`V/V` virtual
entries. 12 of the 40 carry `*`:
inodes 7, 23, 38, 50, 53, 68, 80, 83, 95, 98, 113, 125. The names are real long names,
not 8.3 stubs, because `fixtures/fat32.py` writes VFAT LFN entries
(architecture.md D1, operator decisions).

Names surviving deletion is not recovery. `fls -l` prints size 0 for every one of the 12:

```
$ fls -r -p -l out/fixture.img
r/r * 7:	evidence_log_2026-01-14.txt	...	0	0	0
r/r 11:	interview_transcript_raw.txt	...	62265	0	0
```

### 1.2 · The deleted entries are stripped, not merely unlinked

```
$ istat out/fixture.img 7
Directory Entry: 7
Not Allocated
Size: 0
Name: _VIDEN~1.TXT
Sectors:
2064
```

Sector 2064 is inside the reserved area, not a data cluster — `istat` is reporting a
first cluster of 0. Reading the raw root directory at sector 2072 confirms it for all 12:

```
$ python3 - <<'PY'   # 32-byte FAT directory entries at 2072*512
DEL name='åVIDEN~1TXT' first_cluster=0 size=0
    name='INTERV~1TXT' first_cluster=92948 size=62265
DEL name='åUDIT_~1GZ ' first_cluster=0 size=0
DEL name='åECTOR~1PNG' first_cluster=0 size=0
... 12 deleted entries, every one first_cluster=0 size=0
PY
```

This matters because the usual FAT recovery trick — assume the file was contiguous from
the recorded start cluster — is unavailable. There is no start cluster. TSK is not being
handicapped by our fixture out of malice; it is being handed the case that a real
sanitization tool leaves behind, which is metadata gone and data still resident.

The link is severed in both directions:

```
$ ifind -d 391036 out/fixture.img      # first sector of deleted seizure_photo_b.jpg
Inode not found
$ ffind out/fixture.img 391036
(no output)
$ blkstat out/fixture.img 391036
Sector: 391036
Not Allocated
Cluster: 97243

$ ifind -d 246092 out/fixture.img      # first sector of LIVE platter_surface_01.jpg
62
$ blkstat out/fixture.img 246092
Sector: 246092
Allocated
Cluster: 61007
```

### 1.3 · `icat` and `tsk_recover -a`: 28 of 40, all byte-exact

Every inode from `fls` was piped through `icat` and hashed:

```
$ for ino in ...; do icat out/fixture.img $ino > $ino.bin; shasum -a 256 $ino.bin; done
```

| `icat` result | files |
|---|---|
| SHA-256 equals the manifest digest | 28 |
| 0 bytes returned (`e3b0c442…7852b855`, the empty digest) | 12 |
| wrong bytes returned | 0 |

`tsk_recover` agrees exactly, and its two modes are the whole story in four lines:

```
$ tsk_recover out/fixture.img rec_u        # default: unallocated only
Files Recovered: 0

$ tsk_recover -a out/fixture.img rec_a     # all files
Files Recovered: 28
```

All 28 files written by `tsk_recover -a` hash to their manifest digests. **0 of the 12
deleted files were recovered by any metadata-driven TSK path.**

`sorter`, TSK's type-identification tool, is metadata-driven too and covers the same set:

```
$ sorter -l -md5 out/fixture.img
Category: text
interview_transcript_raw.txt
ASCII text
Image: out/fixture.img  Inode: 11
MD5: 80422c2db327eb00c7e23c548d0248ff
...
```

28 distinct inodes indexed — 11, 14, 17, 20, 26, 29, 32, 35, 41, 44, 47, 56, 59, 62, 65,
71, 74, 77, 86, 89, 92, 101, 104, 107, 110, 116, 119, 122 — the live set exactly, and
none of the 12 deleted. Its categories: 8 text, 7 images, 3 documents, 10 Unknown.

### 1.4 · TSK 4.15.0 ships no file carver

The installed binaries are `blkcalc blkcat blkls blkstat fcat ffind fiwalk fls fsstat
hfind icat ifind ils img_cat img_stat istat jcat jls jpeg_extract mactime mmcat mmls
mmstat pstat sigfind sorter srch_strings tsk_comparedir tsk_gettimes tsk_imageinfo
tsk_loaddb tsk_recover usnjls`. None of them reassembles an object from raw bytes.
`blkls` produces the stream a carver consumes; `sigfind` locates a byte pattern.
Turning either into files is left to a separate tool, which in this project is ours.

---

## 2 · Head-to-head over the whole image

```
$ ./core/target/release/carve out/fixture.img \
      --manifest out/fixture.manifest.json --phase pre-wipe -o carve.json
carve: image out/fixture.img  268435456 bytes  sha256 d85612b2…8ac2df41
carve: gate 0.7500  dedup on  rejected-records reported  residue-window per-kind size_bounds().full_lo
carve: scanned 92 candidates, suppressed 34 overlapping, recorded 58
carve: admitted 33  rejected 25
carve: wall clock 1.639 s over 268435456 bytes
carve: SHA-256 cross-check against out/fixture.manifest.json — 28 of 40 planted files recovered byte-exact
carve: demonstrated recall (contiguous engine) 28 of 40 planted. Reachability CEILING, a
       different number: contiguous 28, needs bifragment 5, unreachable by construction 7.
carve: WARNING 4 admitted record(s) sit at a planted file's offset but do not hash to it
```

The gate is `confidence::MIN_CONFIDENCE`, read from the crate and printed as 0.7500.

### 2.1 · The 40 rows

`fls/icat` is the metadata path of section 1. `blkls+carve` is the carving path of
section 3. `carve(image)` is the run above. `conf` is that run's `confidence.total` for
the admitted record whose SHA-256 equals the planted digest.

| planted file | kind | state | layout | inode | fls/icat | blkls+carve | carve(image) | conf |
|---|---|---|---|---|---|---|---|---|
| evidence_log_2026-01-14.txt | TXT | deleted | contiguous | 7 | 0 bytes | — | — | — |
| interview_transcript_raw.txt | TXT | live | contiguous | 11 | byte-exact | — | — | — |
| sector_survey_notes.txt | TXT | live | contiguous | 14 | byte-exact | — | — | — |
| operator_handover.txt | TXT | live | contiguous | 17 | byte-exact | — | — | — |
| wipe_command_history.txt | TXT | live | contiguous | 20 | byte-exact | — | — | — |
| audit_trail.log.gz | GZIP | deleted | contiguous | 23 | 0 bytes | byte-exact | byte-exact | 0.9000 |
| dmesg_capture.log.gz | GZIP | live | contiguous | 26 | byte-exact | — | byte-exact | 0.9000 |
| controller_dump.bin.gz | GZIP | live | contiguous | 29 | byte-exact | — | byte-exact | 0.9000 |
| carve_session.log.gz | GZIP | live | contiguous | 32 | byte-exact | — | byte-exact | 0.9000 |
| imaging_transcript.txt.gz | GZIP | live | fragmented | 35 | byte-exact | — | — | — |
| sector_map_01.png | PNG | deleted | contiguous | 38 | 0 bytes | byte-exact | byte-exact | 1.0000 |
| sector_map_02.png | PNG | live | contiguous | 41 | byte-exact | — | byte-exact | 1.0000 |
| sector_map_03.png | PNG | live | contiguous | 44 | byte-exact | — | byte-exact | 1.0000 |
| seizure_photo_a.png | PNG | live | contiguous | 47 | byte-exact | — | byte-exact | 1.0000 |
| entropy_heatmap.png | PNG | deleted | fragmented | 50 | 0 bytes | — | — | — |
| seizure_photo_b.jpg | JPEG | deleted | contiguous | 53 | 0 bytes | byte-exact | byte-exact | 1.0000 |
| drive_label_macro.jpg | JPEG | live | contiguous | 56 | byte-exact | — | byte-exact | 1.0000 |
| bench_setup_wide.jpg | JPEG | live | contiguous | 59 | byte-exact | — | byte-exact | 1.0000 |
| platter_surface_01.jpg | JPEG | live | contiguous | 62 | byte-exact | — | byte-exact | 1.0000 |
| evidence_bag_seal.jpg | JPEG | live | fragmented | 65 | byte-exact | — | — | — |
| chain_of_custody.pdf | PDF | deleted | contiguous | 68 | 0 bytes | byte-exact | byte-exact | 1.0000 |
| acquisition_worksheet.pdf | PDF | live | contiguous | 71 | byte-exact | — | byte-exact | 1.0000 |
| standards_checklist.pdf | PDF | live | contiguous | 74 | byte-exact | — | byte-exact | 1.0000 |
| examiner_affidavit.pdf | PDF | live | contiguous | 77 | byte-exact | — | byte-exact | 1.0000 |
| disposal_certificate.pdf | PDF | deleted | fragmented | 80 | 0 bytes | — | — | — |
| sanitization_report.docx | DOCX | deleted | contiguous | 83 | 0 bytes | byte-exact | byte-exact | 1.0000 |
| incident_summary.docx | DOCX | live | contiguous | 86 | byte-exact | — | byte-exact | 1.0000 |
| lab_procedure_v3.docx | DOCX | live | contiguous | 89 | byte-exact | — | byte-exact | 1.0000 |
| custody_addendum.docx | DOCX | live | contiguous | 92 | byte-exact | — | byte-exact | 1.0000 |
| media_inventory.docx | DOCX | deleted | fragmented | 95 | 0 bytes | — | — | — |
| custody_ledger.db | SQLITE | deleted | contiguous | 98 | 0 bytes | byte-exact | byte-exact | 0.9000 |
| sector_index.db | SQLITE | live | contiguous | 101 | byte-exact | — | byte-exact | 0.9000 |
| device_registry.db | SQLITE | live | contiguous | 104 | byte-exact | — | byte-exact | 0.9000 |
| carve_results.db | SQLITE | live | contiguous | 107 | byte-exact | — | byte-exact | 0.9000 |
| hash_baseline.db | SQLITE | live | contiguous | 110 | byte-exact | — | byte-exact | 0.9000 |
| bodycam_intake.mov | MP4 | deleted | contiguous | 113 | 0 bytes | byte-exact | byte-exact | 0.9000 |
| bench_capture_01.mov | MP4 | live | contiguous | 116 | byte-exact | — | byte-exact | 0.9000 |
| drive_teardown.mov | MP4 | live | contiguous | 119 | byte-exact | — | byte-exact | 0.9000 |
| sealing_procedure.mov | MP4 | live | fragmented | 122 | byte-exact | — | — | — |
| handover_briefing.mov | MP4 | deleted | fragmented | 125 | 0 bytes | — | — | — |

### 2.2 · Agreement

| | count | which |
|---|---|---|
| both byte-exact | 21 | live, contiguous, signature-bearing |
| **TSK only** | **7** | 4 live plaintext + 3 live fragmented |
| **carver only** | **7** | the deleted contiguous signature-bearing set |
| neither | 5 | 1 deleted plaintext + 4 deleted fragmented |
| union | **35 of 40** | |

Both tools land on 28 of 40. **They are not the same 28.** That is the entire result of
this cross-check, and it is why the locked stack calls TSK a cross-check rather than a
competitor: the two coverage sets are complementary, and each names the other's blind
spot.

Zero rows disagree on content. In all 21 rows where both tools produced bytes for the
same file, the digests match each other and the manifest. There is no case in this image where TSK
and the carver hand you different bytes and claim the same file.

---

## 3 · The carving path — `blkls`, and what carving actually adds

Section 1 established that no metadata-driven TSK tool recovers any of the 12 deleted
files. The data is still there; only the pointers are gone. `blkls` proves it by handing
over the bytes:

```
$ blkls out/fixture.img > unalloc.blkls          # 0.309 s
$ ls -l unalloc.blkls
263948288 unalloc.blkls
$ shasum -a 256 unalloc.blkls
f498ab02b8ea3eb208d8985c7c947eb49e4139b7416134708f32765ee242ee65
```

263948288 bytes of unallocated clusters, 98.3% of the image. This is where the deleted
evidence lives and it is exactly the input a carver is for. **TSK's own answer over this
stream is `tsk_recover` → `Files Recovered: 0`.** It supplies the haystack and declines
to search it.

Ours, over TSK's stream and nothing else:

```
$ ./core/target/release/carve unalloc.blkls --manifest out/fixture.manifest.json -o carve_blkls.json
carve: image out/fixture.unalloc.blkls  263948288 bytes  sha256 f498ab02…e242ee65
carve: scanned 45 candidates, suppressed 10 overlapping, recorded 35
carve: admitted 10  rejected 25
carve: wall clock 1.622 s over 263948288 bytes
carve: SHA-256 cross-check against out/fixture.manifest.json — 7 of 40 planted files recovered byte-exact
```

| deleted file | conf | TSK over the same stream |
|---|---|---|
| sector_map_01.png | 1.0000 | not recovered |
| seizure_photo_b.jpg | 1.0000 | not recovered |
| chain_of_custody.pdf | 1.0000 | not recovered |
| sanitization_report.docx | 1.0000 | not recovered |
| audit_trail.log.gz | 0.9000 | not recovered |
| custody_ledger.db | 0.9000 | not recovered |
| bodycam_intake.mov | 0.9000 | not recovered |

Seven files, byte-exact against digests computed independently by `fixtures/build_image.py`,
each with a score and a published derivation. This is the row that carries the project:
the same 263948288 bytes went into both tools, and one of them came back with named
evidence and a number attached to each piece.

The other 3 admitted records over the `blkls` stream match nothing in the manifest by
digest and are reported in section 5.2: `PNG@49219584` at 0.9394, 185398 bytes, whose
SHA-256 is identical to the leading fragment of entropy_heatmap.png recovered in the
whole-image run; `MP4@63711232` at 0.9000, 66689 bytes, the leading region of
handover_briefing.mov, which is *not* byte-identical to its whole-image counterpart
because removing the allocated clusters changes what follows the fragment; and
`ZIP@163643` at 0.7550, 1752 bytes, byte-identical to the false positive `ZIP@1228603`
of section 5.2 and no more a file here than it was there.

---

## 4 · Signature scanning, head to head

`sigfind` is the only pattern scanner TSK ships. At its default it is sector-granular:

```
$ sigfind -b 512 ffd8ff out/fixture.img | grep -c '^Block:'
5
$ sigfind -b 512 1f8b08 out/fixture.img | grep -c '^Block:'
5
$ sigfind -b 512 425a68 out/fixture.img | grep -c '^Block:'
0
```

Block sizes below 512 are rejected outright — `Invalid block size`, tested at 1, 2, 256
and 511 — and it tests the pattern at exactly one offset inside each block. So at defaults it finds
the 5 cluster-aligned planted JPEGs and the 5 cluster-aligned planted GZIPs and nothing
else. It misses every unaligned header, decoy or genuine, silently.

To compare like with like, `sigfind` was swept across all 512 intra-sector offsets, which
makes it byte-granular over the whole image. (`-o 0` is rejected by its argument parser —
`Error converting offset value: 0` — so offset 0 is covered by the default run.)

```
$ sigfind -b 512 ffd8ff out/fixture.img | awk '/^Block:/{print $2*512}'
$ for o in $(seq 1 511); do
    sigfind -b 512 -o $o ffd8ff out/fixture.img | awk -v o=$o '/^Block:/{print $2*512+o}'
  done
```

| signature | sigfind, sector-aligned | sigfind, byte-granular sweep | `carve --no-dedup` candidates |
|---|---|---|---|
| `ffd8ff` JPEG SOI | 5 | **19** | **19** |
| `1f8b08` GZIP | 5 | **18** | **18** |
| `425a68` BZ2 | 0 | 12 | 0 — no BZ2 row in `signature::SIGNATURES` |

For JPEG and GZIP the two offset lists are **identical, element for element** — set
difference empty in both directions. The scanners agree completely about where the
headers are. Everything that follows is about what is said next.

### 4.1 · The 21 residue decoys

The manifest plants 21 residue decoys our signature table can see:
`residue_signature_false_positives` = 8 JPEG, 13 GZIP.

**Is TSK fooled by them?** The precise answer, which is worth more than a slogan: no TSK
tool ever offers them as files, because no TSK tool carves. What `sigfind` does is report
all 21 as offsets, formatted identically to the 10 real ones, ranked by nothing, annotated
with nothing. It has no mechanism to reject them and no mechanism to prefer the real ones.
The discrimination is left entirely to the examiner.

Our carver's verdict on the same 19 JPEG offsets:

| offset | verdict | confidence | structural_validity | planted file |
|---|---|---|---|---|
| 125999104 | admitted | 1.0000 | 1.0000 | platter_surface_01.jpg |
| 156942336 | admitted | 1.0000 | 1.0000 | bench_setup_wide.jpg |
| 176111616 | admitted | 1.0000 | 1.0000 | drive_label_macro.jpg |
| 200210432 | admitted | 1.0000 | 1.0000 | seizure_photo_b.jpg |
| 214231040 | admitted | 0.9300 | 0.8000 | evidence_bag_seal.jpg (leading fragment) |
| 18325159 | rejected | 0.6500 | 0.0000 | — residue |
| 35205775 | rejected | 0.6446 | 0.0000 | — residue |
| 44064338 | rejected | 0.5680 | 0.0000 | — residue |
| 88398058 | rejected | 0.6386 | 0.0000 | — residue |
| 126324818 | rejected | 0.6196 | 0.0000 | — residue |
| 180788456 | rejected | 0.6500 | 0.0000 | — residue |
| 255993614 | rejected | 0.6500 | 0.0000 | — residue |
| 256383792 | rejected | 0.6500 | 0.0000 | — residue |
| 21414349, 133209684, 136978331, 180548490, 180577290, 180644692 | suppressed | 0.6500 | 0.0000 | SOI interior to an already-recovered object |

and on the 18 GZIP offsets: 4 admitted at 0.9000, every one byte-exact against its planted
digest, plus 1 at 0.7600 (imaging_transcript.txt.gz, leading fragment); 13 rejected between
0.4750 and 0.5625.
One of those 13, at offset 173564124, earns 0.2500 of genuine structural credit — its
GZIP header parses and only the DEFLATE stream fails — which is the live margin
architecture.md D2 describes.

Across all 21 manifest-counted decoys the highest score is 0.6500, against a gate of
0.7500. No decoy was admitted. `structural_validity` is 0.0000 for 20 of the 21 and
0.2500 for the twenty-first; the gate is breached at
`STRUCTURAL_BREACH_POINT` = 0.285714, so the margin that actually binds is **0.0357**.

Stated as plainly as it can be: `sigfind` and our scanner found the same 37 JPEG and GZIP
headers. TSK returned 37 offsets. We returned 10 admissions with a per-term derivation, 21
rejections with a reason code and 6 suppressions as interior to an already-recovered
object — and the 21 planted traps are exactly the rejection set.

---

## 5 · Where each tool is worse

Nothing here is rounded in our favour.

### 5.1 · TSK strictly beats the carver on 7 files

| file | why the carver fails |
|---|---|
| interview_transcript_raw.txt | plaintext: no row in `signature::SIGNATURES`, no header to scan for |
| sector_survey_notes.txt | same |
| operator_handover.txt | same |
| wipe_command_history.txt | same |
| imaging_transcript.txt.gz | fragmented; `bifragment.rs` deferred, not called |
| evidence_bag_seal.jpg | 2 extents stored in reverse physical order; a forward gap search cannot reach them |
| sealing_procedure.mov | fragmented; `bifragment.rs` deferred, not called |

The plaintext deficit is real and structural. A signature carver cannot see a file that
has no signature, and four of the five plaintext files are live, so `icat` reads them out
of the directory entry in microseconds while we return nothing at all. On a live
filesystem with intact metadata, TSK is the better tool and this document says so.

The fifth plaintext file, `evidence_log_2026-01-14.txt`, is deleted — and there neither
tool recovers anything: no metadata for TSK to follow, no signature for us to find.

### 5.2 · The carver admits records TSK would never produce, including a wrong one

The whole-image run admits 33 records; 28 hash to a planted file. The other 5:

| record | conf | length | what it is |
|---|---|---|---|
| PNG@51361792 | 0.9394 | 185398 | leading fragment of entropy_heatmap.png |
| JPEG@214231040 | 0.9300 | 53062 | leading fragment of evidence_bag_seal.jpg |
| MP4@65943552 | 0.9000 | 66689 | leading fragment of handover_briefing.mov |
| GZIP@143464448 | 0.7600 | 69712 | leading fragment of imaging_transcript.txt.gz |
| **ZIP@1228603** | **0.7550** | **1752** | **no planted file — a self-consistent ZIP structure interior to the tri-fragment DOCX** |

The first four are partial recoveries of a real file, each flagged in the report by
`ground_truth.sha256_matches: false` and by the stderr warning
`4 admitted record(s) sit at a planted file's offset but do not hash to it`.
The fifth is a plain false positive: an admitted record, above the gate, corresponding to
no planted file. It is the run's `lowest_admitted` at 0.7550, 0.0050 above the gate.

TSK produces no such artefact, because it produces no artefact at all here. **On precision
over a stream, a tool that carves nothing cannot be wrong.** That is a real property and
it is the cost side of the carving ledger: 7 files TSK cannot reach, bought with 1 admitted
record that is not a file and 4 that are fragments of one.

### 5.3 · Kinds the carver does not scan

`sigfind` finds 12 `425a68` occurrences; the manifest plants 11 BZ2 residue decoys and no
BZ2 file among the 40. Our signature table has no BZ2 row, so the carver scans zero of
them. No planted file is missed by this, but it is an unmeasured surface: a BZ2 object on
a real drive would be invisible to us and visible to `sigfind`.

---

## 6 · Cost

One run each, this machine, warm page cache.

| command | wall clock |
|---|---|
| `fls -r -p out/fixture.img` | 0.076 s |
| `tsk_recover out/fixture.img …` (deleted only) | 0.062 s |
| `tsk_recover -a out/fixture.img …` | 0.070 s |
| `blkls out/fixture.img > unalloc.blkls` | 0.309 s |
| `carve out/fixture.img --manifest …` | 1.655 s over 268435456 bytes |
| `carve unalloc.blkls --manifest …` | 1.658 s over 263948288 bytes |
| `sigfind` byte-granular sweep, one signature, 512 invocations | 25.540 s |

Metadata parsing is an index lookup and carving is a full read; the distance between
0.070 s and 1.655 s is that difference and not an inefficiency. The `sigfind`
figure is the cost of 512 separate process launches over the same 256 MB and is reported
to show what byte-granular scanning costs when the tool is sector-granular by design.

---

## 7 · Limits of this cross-check

- One image, one filesystem. FAT32 only. TSK's strongest ground is NTFS and ext4 journal
  recovery, none of which is exercised here.
- The 12 deleted files are stripped to `first_cluster=0 size=0`. A deletion that leaves
  the start cluster intact — which many FAT implementations do — would let `icat` and
  `tsk_recover` recover contiguous deleted files, and the carver-only column would shrink.
  That case is not measured.
- `sigfind` was compared on 3 signatures. TSK's `-t` templates were not exercised.
- `blkls` output was carved as one flat stream. A file whose clusters are unallocated but
  non-adjacent in the stream is not addressed by this run, which carves contiguously.
- Every recall figure here is **demonstrated recall (contiguous engine)**, measured by
  SHA-256. The reachability ceiling for this image is a separate number reported separately
  by `carve` itself, and the two are never added.
