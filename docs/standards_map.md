# Standards map

Every sanitization claim carries its clause. An officer reads this table before they read
the code.

Sources cited, never paraphrased: **NIST SP 800-88 Rev. 1** (Clear / Purge / Destroy),
**IEEE 2883-2022**, and **DoD 5220.22-M** where legacy expectation demands it.

A row is added when the operation is implemented and its verification has actually run.
**The final column is never empty:** an operation with nothing in it has not been examined
honestly enough yet.

> **On clause numbers.** The category names below — Clear, Purge, Destroy — are the
> canonical NIST SP 800-88 Rev. 1 sanitization categories and are cited with confidence.
> Section and table numbers are deliberately *not* asserted here: they must be checked
> against the published document before this table goes in front of a jury, and inventing
> one in a file whose title says "cite, do not paraphrase" would be worse than omitting it.

---

## Implemented and measured

| our operation | standard | category | what we verified | what we could NOT verify |
|---|---|---|---|---|
| Single-pass overwrite, seeded SHAKE-128 stream, with sampled read-back | NIST SP 800-88 Rev. 1 | **Clear** | Pattern confirmed on 1,024 of 524,288 sectors. Whole-image entropy moved 7.061690 → 7.999999 bits/byte, same estimator both sides. Outcome `OVERWRITE_VERIFIED_ON_SAMPLE`, `whole_medium_claim: false`. | 99.8047% of sectors were not read back. The largest run the sampling plan never touches is **2,815 sectors (0.5369% of the medium)**; a region left unwiped inside it passes a sampled verdict. `--verify exhaustive` closes this and is not the default. |
| Single-pass zero overwrite | NIST SP 800-88 Rev. 1 | **Clear** | Same sampled read-back path. | Same sampling limit. Zero-fill also *lowers* whole-image entropy, so entropy is not evidence of erasure for this method. |
| 3-pass overwrite | NIST SP 800-88 Rev. 1 (legacy expectation: DoD 5220.22-M) | **Clear** | Each pass verified independently by sampled read-back. | Same sampling limit per pass. NIST does not require 3 passes for modern media; it is offered because evaluators still ask for it. |
| Behavioural timing audit on any sanitize claim | NIST SP 800-88 Rev. 1 — verification guidance | supports **Clear** and **Purge** | A simulated `ATA SANITIZE BLOCK ERASE` returned in 1,000 ns against a floor of 431,059,458 ns derived from a measured 622,734,175 B/s — 431,059× faster than physically possible. Verdict `UNVERIFIED_TIMING`. Corroborated independently: `medium_unchanged: true` over 256 sampled sectors. | Timing cannot prove an erase *happened* when the duration looks plausible. A device that fakes host writes fast enough would inflate the measured baseline and disarm the audit. Only read-back addresses that, and read-back is sampled. |
| Stating verification limits on the certificate | NIST SP 800-88 Rev. 1 — documentation guidance | applies to all | The limitations section is mandatory, non-empty, and rendered in amber rather than hidden. Coverage fraction and `sanitized_scope` appear on the artifact's face. | The certificate is not yet signed. Ed25519 and Merkle anchoring are Phase 4. |

## Claimed by the interface, simulated in this build

Each of these dispatches only where a device claims support. On an image file **no firmware
command is issued**, the word `simulated` appears in the operation name and in the record,
and the behavioural audit refuses the claim outright.

| our operation | standard | category | what we verified | what we could NOT verify |
|---|---|---|---|---|
| ATA SANITIZE BLOCK ERASE | NIST SP 800-88 Rev. 1 · IEEE 2883-2022 | **Purge** | Nothing. The dispatch path, the `simulated` labelling, and the audit's refusal are verified. | That the primitive erases anything. No real ATA device has been issued this command by this software. |
| NVMe Sanitize (block erase) | NIST SP 800-88 Rev. 1 · IEEE 2883-2022 | **Purge** | As above. | As above. |
| NVMe Sanitize / Format (crypto erase) | NIST SP 800-88 Rev. 1 · IEEE 2883-2022 | **Purge** | As above. | As above. Crypto-erase is judged as constant-time by design, not against full-capacity write time. |

## Out of scope, stated rather than half-built

| operation | standard | why not |
|---|---|---|
| Destroy (degauss, shred, disintegrate) | NIST SP 800-88 Rev. 1 | **Destroy** is physical. Software cannot perform or verify it, and claiming otherwise would be dishonest. |
| SSD over-provisioned block purge verification | NIST SP 800-88 Rev. 1 · IEEE 2883-2022 | Host-addressable reads cannot reach remapped or over-provisioned blocks. NIST itself advises stating this limit rather than asserting a clean purge. |
| Live TRIM analysis, multi-terabyte scanning, APFS | — | Out until nationals. Named on the slide rather than half-built. |

---

## The rule this table exists to enforce

CLAUDE.md rule 1: **the tool never claims more than it verified.** Where a category is
claimed and not proven, the certificate says so in that field — not in a footnote, and not
by omission. A simulated purge is never printed as a verified purge.
