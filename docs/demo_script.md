# Demo script · 90 seconds

Written before any code, and the build is derived from it. If a feature does not
appear in these 90 seconds, it does not get built before the internal round.

One narrator across every jury visit.

| Time | Action | Line |
|---|---|---|
| 0:00 | | "Forty files on this drive. Deleted, not erased — the ordinary case." |
| 0:10 | carve runs | "Twenty-eight of forty, verified byte-exact. The engine admits thirty-three and we show you which five do not match, and why. No number on this screen is a count we did not check against a hash." |
| 0:30 | sector map sweeps, hex changes, entropy climbs from a measured 7.0617 bits/byte | "Now we sanitize. NIST 800-88, method chosen by medium — not one-size-fits-all." |
| 0:50 | | "Erasure tools tell you they worked. We don't ask you to believe us." |
| 0:55 | carve runs again, identical parameters, table stays empty | "Zero of forty. Verified by the same engine that found twenty-eight a minute ago." |
| 1:10 | certificate seals | "Signed, hash-chained, with its own limitations printed on it." |
| 1:20 | TAMPER | "And if anyone alters the record — it says so." |
| 1:30 | | Stop talking. |

## Notes for the narrator

- The empty carve table at 0:55 is the climax. Do not narrate over it and do not
  fill it with a graphic. Let the jury watch a scan run and find nothing.
- Say twenty-eight, and be ready to break the twelve down: five plaintext files that
  carry no signature any carver could key on, five stored in non-contiguous fragments
  that the reassembly stage will close, and two we fragmented deliberately to defeat
  our own engine — a three-fragment DOCX and a JPEG whose second fragment sits
  physically before its first. The last two are ours on purpose. A recovery engine
  that scored full marks on a test we wrote ourselves would be the weakest claim in
  the deck; naming its failures is what makes the zero at 0:55 worth believing.
- TWENTY-EIGHT AND THIRTY-THREE ARE DIFFERENT NUMBERS AND BOTH ARE TRUE. The engine
  admits 33 objects above the 0.7500 confidence gate. Against the ground truth we
  planted, 28 of those are byte-exact. Four of the other five are the leading fragment
  of a file stored in pieces — real data, correctly identified, incompletely assembled.
  The fifth, a ZIP at offset 1228603, is a genuine false positive, and it scores
  0.7550: barely over the gate, the lowest admitted score on the screen. Do not hide
  it. A tool that shows you its weakest admission and tells you why it is weak is the
  argument; a tool that shows 33 and calls them all recoveries is every other tool.
- Never say the reachability ceiling as if it were a recall figure. 33 of 40 is what
  this fixture makes reachable in principle; 28 of 40 is what the engine demonstrated.
  They never belong in the same sentence.
- The demo runs the DEFAULT path: contiguous carving, 2.3 seconds, 28 of 40. Fragment
  reassembly is a flag and it is OFF on stage, deliberately. Turning it on finds two
  more files and takes 66 seconds — forty times the cost for two files, which does not
  fit a 90-second demo and should not pretend to.
- IF ASKED WHAT THE CONFIDENCE SCORE MEANS, this is the answer, and it is the best
  thing in the deck after the adversarial loop. A score says "this is a well-formed
  object of this type." It does NOT say "these are the original bytes." For formats
  carrying integrity checks over their payload — PNG chunk CRCs, GZIP CRC32, ZIP
  per-entry CRCs — those two claims nearly coincide. For JPEG entropy-coded data and
  MP4 sample data there is no such check, and they can diverge completely.
  We have a case on screen: handover_briefing.mov is admitted at 0.9000 with a perfect
  structural score and a length matching the planted file to the byte — and a different
  SHA-256. No term fell short. The formula did exactly what it claims and was still
  wrong. That is why we join recovery to ground truth by hash rather than by row count,
  and why the four terms are on screen instead of a single number. In the field there
  is no manifest to join against; the published score is what stands in for it, and it
  has to be honest about what it can and cannot see.
- If asked "can you recover fragmented files": yes, and say the number honestly. Two of
  the five fragmented files reassemble byte-exact. Of the other three, one is a gap in
  our PDF validator that we can close; one is a limit of the QuickTime format itself —
  mdat declares its own length, so 6,660 different splices all validate and no byte in
  the format distinguishes them, which no carver can fix; and one our MP4 validator
  wrongly accepts whole, so the search never runs. That answer is worth more than a
  higher number, because the second case is a fact about forensics rather than about us.
- If asked why plaintext cannot be carved: signature carving keys on magic bytes and
  plain text has none. Our corpus text does open with an ASCII banner, and keying on it
  would lift the number to thirty-eight in an afternoon. We did not, because a carver
  tuned to a marker we planted ourselves measures nothing. That answer is worth more
  than the five files.
- Every figure in this script is measured and traceable to out/fixture.manifest.json.
  The pre-wipe entropy of 7.0617 bits/byte is whole-image, recomputed on the built
  artifact. The post-wipe figure is written here once Phase 3 measures it, not before.
- If the wipe overruns the budget, shrink the fixture to 64 MB. Never shrink the
  loop — carve, wipe, carve, sign is the whole pitch.
- Open on the standards table, not the architecture diagram. For this audience,
  "NIST SP 800-88 Rev. 1, clause cited per operation" lands harder than any box
  diagram.
- Demo mode replays a recorded telemetry trace. A live filesystem operation never
  stands between the team and a working demo in front of faculty.
