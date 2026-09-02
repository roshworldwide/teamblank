# Demo script · 90 seconds

Written before any code, and the build is derived from it. If a feature does not
appear in these 90 seconds, it does not get built before the internal round.

One narrator across every jury visit.

| Time | Action | Line |
|---|---|---|
| 0:00 | | "Forty files on this drive. Deleted, not erased — the ordinary case." |
| 0:10 | carve runs | "Thirty-three of forty. Five are plaintext with no signature to carve. Two more we fragmented deliberately to defeat our own engine — three pieces, and one stored backwards. It names all seven rather than guessing." |
| 0:30 | sector map sweeps, hex changes, entropy climbs from a measured 7.0617 bits/byte | "Now we sanitize. NIST 800-88, method chosen by medium — not one-size-fits-all." |
| 0:50 | | "Erasure tools tell you they worked. We don't ask you to believe us." |
| 0:55 | carve runs again, identical parameters, table stays empty | "Zero of forty. Verified by the same engine that found thirty-three a minute ago." |
| 1:10 | certificate seals | "Signed, hash-chained, with its own limitations printed on it." |
| 1:20 | TAMPER | "And if anyone alters the record — it says so." |
| 1:30 | | Stop talking. |

## Notes for the narrator

- The empty carve table at 0:55 is the climax. Do not narrate over it and do not
  fill it with a graphic. Let the jury watch a scan run and find nothing.
- Say thirty-three, not forty, and be ready to break the seven down: five plaintext
  files that carry no signature any carver could key on, plus a three-fragment DOCX and
  a JPEG whose second fragment sits physically before its first. The last two are ours
  on purpose. A recovery engine that scored full marks on a test we wrote ourselves
  would be the weakest claim in the deck; naming its failures is what makes the zero at
  0:55 worth believing.
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
