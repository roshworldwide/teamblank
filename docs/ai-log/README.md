# AI log

A record of what was asked of the assistant, what it produced, and where it was
wrong. Two purposes, in this order:

1. **Engineering.** A rejected output that is written down once does not have to be
   re-diagnosed three phases later.
2. **The jury.** SIH juries ask how much of this you wrote. The honest answer is
   stronger than the evasive one, and it is only available if the log exists. A
   team that can name its own AI failure modes reads as engineers; a team that
   claims it wrote everything unaided reads as either lying or lucky.

## Protocol — followed unprompted, every task

### After every task: append to `entries/YYYY-MM-DD.md`

```markdown
## HH:MM · <short title>

**Asked.**    What the prompt requested, in one or two sentences.
**Produced.** Files touched, decisions taken, commands run.
**Unsure.**   What has not been verified, what was guessed, what could be wrong.
```

The **Unsure** field is the point of the entry. An entry that claims full
confidence in everything is an entry that was not worth writing.

### On rejection: write `rejected/NNN-slug.md` immediately

Immediately means before the corrected attempt, not after it. The corrected
version overwrites the memory of what went wrong.

```markdown
# NNN · <slug>

**Date.**    YYYY-MM-DD
**Phase.**   1..6

## The prompt
Verbatim.

## What was produced
The wrong output, or the diff of it. Quote it; do not summarise it.

## Why it was wrong
The specific defect. Not "it was bad" — the rule it broke, from CLAUDE.md where
one applies.

## The test that caught it
Name it: a pytest node id, a `cargo test` name, a `make verify` row, or a human
reading it. If nothing automated caught it, say so and state whether a test now
exists that would.
```

`NNN` is a zero-padded sequence, `001` upward, never reused.

## Rules

- One file per day in `entries/`, appended to; never rewritten.
- One file per rejection in `rejected/`; never deleted.
- No entry is retroactively edited to look better. The log's value is that it is
  not curated.
