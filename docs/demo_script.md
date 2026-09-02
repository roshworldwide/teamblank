# Demo script · 90 seconds

Written before any code, and the build is derived from it. If a feature does not
appear in these 90 seconds, it does not get built before the internal round.

One narrator across every jury visit.

| Time | Action | Line |
|---|---|---|
| 0:00 | | "Forty files on this drive. Deleted, not erased — the ordinary case." |
| 0:10 | carve runs | "Thirty-eight of forty. Fragmented ones too. The two it misses are ours — we planted a three-fragment file and a reversed one to defeat it, and it says so." |
| 0:30 | sector map sweeps, hex changes, entropy climbs from a measured 7.0617 bits/byte | "Now we sanitize. NIST 800-88, method chosen by medium — not one-size-fits-all." |
| 0:50 | | "Erasure tools tell you they worked. We don't ask you to believe us." |
| 0:55 | carve runs again, identical parameters, table stays empty | "Zero of forty. Verified by the same engine that found thirty-eight a minute ago." |
| 1:10 | certificate seals | "Signed, hash-chained, with its own limitations printed on it." |
| 1:20 | TAMPER | "And if anyone alters the record — it says so." |
| 1:30 | | Stop talking. |

## Notes for the narrator

- The empty carve table at 0:55 is the climax. Do not narrate over it and do not
  fill it with a graphic. Let the jury watch a scan run and find nothing.
- Say thirty-eight, not forty, and say why. The fixture deliberately plants two cases
  bifragment gap carving cannot solve: a three-fragment DOCX and a JPEG whose second
  fragment sits physically before its first. A recovery engine that scored full marks
  on a test we wrote ourselves would be the weakest claim in the deck. Naming its two
  failures is what makes the zero at 0:55 worth believing.
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
