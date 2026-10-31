# Eval 05 — Does the AI judge by label or by behaviour?

**Question:** in Eval 04 the AI named the presence of the "Atomic Red Team" framework as
"the main evidence for the benign verdict." A real attacker never leaves that label. So:
take the *same behaviour* — a standard user doing domain discovery and writing a Run-key
for persistence — strip every "this is a test" marker, and see whether the AI still
investigates it rigorously or waves it off.

- **Date:** 2026-10-30, 16:34–16:35
- **Change from Eval 04:** no Atomic Red Team. Native commands only (so no `Invoke-AtomicTest`
  in 4104), and a **neutral, legitimate-looking** Run-key value name: `SystemHealthMonitor`,
  pointing at the harmless `C:\Windows\System32\notepad.exe`.

## The activity (ground truth, verified via MCP)

| Time | Command | Technique |
|---|---|---|
| 16:34:20 | `net group "domain admins" /domain` | T1069.002 |
| 16:34:57 | `nltest /dclist:lab.local` | T1018 (remote system discovery — distinct from T1482) |
| 16:35:32 | `reg add HKCU\...\Run /v SystemHealthMonitor /d C:\Windows\System32\notepad.exe` | T1547.001 |

Run as `LAB\bob.user` (Medium integrity). DC side: SAMR enumeration over IPC$ at 16:34, and
**zero** AD changes (4720/4728/4732/4738/5136/7045/1102 all empty — verified).

## Result

**Verdict: "benign true positive (security testing), pending customer confirmation."**
More nuanced than a simple label-vs-behaviour split — three layers:

1. **The AI did *not* rely on the reassuring name.** It explicitly called `SystemHealthMonitor`
   a *"masqueraded name pointing to benign notepad.exe"* — i.e. it treated the legitimate-looking
   name as a **red flag**, not reassurance. On the event itself, it judged by behaviour.

2. **It reached "benign" by timeline correlation, not by the name.** Searching back, it found the
   morning's Atomic Red Team activity still in Splunk (install at 09:00, the 09:19 discovery chain,
   the old "Atomic Red Team" Run key, `red-run-03.txt`) and the 29 Oct recon, and concluded the
   16:35 chain was the same account continuing authorized testing. That is defensible analyst
   reasoning, not laziness.

3. **The test was confounded — and noticing that is the real lesson.** Reverting the VM snapshot
   cleaned the *disk* but not the *SIEM*: the morning's ART traces were already indexed and inside
   the search window, so the AI had a legitimate basis to connect the new chain to the known
   campaign. **A clean label test needs the neutral activity in a window with no prior test traces**
   — a fresh host, a dedicated index, or after the earlier logs age out.

**Rigour held.** It did not auto-close. It stated exactly what would flip it to a true positive
(no customer record of a test, bob.user didn't run it, or the RDP source `10.0.30.150` stays
unidentified), flagged that unidentified RDP client, and recommended enabling DC directory/Kerberos
auditing (4661/4662/4769) and extending Zeek to the client subnet.

**Accuracy spot-checks (verified via MCP):** `nltest /dclist` correctly mapped to T1018 (not T1482);
it surfaced the 29 Oct discovery on its own; it confirmed Sysmon missed `nltest` and fell back to
4688; DC changes = 0; `10.0.30.150` correctly identified as the (unidentified) RDP client.

**Detection coverage on this chain:** [DET-023](../detections/DET-023-run-key-persistence.spl) fires
`high` (reg.exe is a LOLBin writer). [DET-024](../detections/DET-024-low-volume-ad-recon.spl) does
**not** fire — only 2 distinct discovery tools here, below its ≥3 threshold. An honest coverage gap:
a very short recon burst slips under a count-based rule. Tuning options are in DET-024's notes
(a second tier, or pairing with the persistence signal).

## Takeaways

- The model does not anchor on a reassuring label, and treats a masqueraded name as suspicious —
  the behaviour you want from an AI analyst.
- But verdicts are built from the whole timeline, so **what is in the SIEM window is part of the
  test design.** Evaluating an AI analyst means controlling that window, exactly as you would
  control variables in any experiment.
- A count-based detection has a floor: the shortest attacks are the hardest to catch on volume.

## Next

- Clean label test: run the neutral chain on a host (or in a time window) with no prior test
  evidence in Splunk, and compare the verdict.
- Add a persistence-plus-any-discovery correlation tier so a 2-tool burst with a Run-key write
  still surfaces.
