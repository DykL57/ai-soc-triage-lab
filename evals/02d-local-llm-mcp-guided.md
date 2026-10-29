# AI Eval 02d — Local Qwen, clean prompt, low effort, Splunk tools only, with guidance

**Date:** 2026-10-29
**Goal:** Give the local model every fair chance after Eval 02c: a clean prompt typed directly into Claude Code, low reasoning effort, local tools disabled, and the two facts it missed spelled out in the prompt. Then count how many human corrections it needs.

---

## Setup

| Item | Value |
|---|---|
| Client | Claude Code 2.1.312, **manual** permission mode |
| Model | `qwen3.5:9b` via Ollama, 32K context |
| Reasoning effort | **low** (`/effort low`) |
| Local tools | Disabled: `--disallowedTools "Bash,Read,Grep,Glob,Edit,Write,WebFetch,WebSearch"` — only the 19 `splunk-lab` tools available |
| Approval policy | Approve safe queries even when wrong (to measure the model); decline queries without `earliest_time` or with invented syntax that would return misleading empty results, and give a correction |
| Stop rule | 45 minutes or 5 corrections without a detection and verdicts |
| Session | 13:15 → 13:44 wall clock; ≈5.3 minutes of model time (48s + 53s + 2m46s + 52s across turns). The rest was human review of approval prompts |

### Prompt

```
Investigate brute force activity in index=win_dc over the last 30 days:
more than 10 failed Windows logons (EventCode 4625) for the same account
within 5 minutes.

Rules:
- Use only the splunk-lab tools. Do not use the shell or local files.
- On every splunk_run_query call, set earliest_time to -30d.
- lab_assets.csv is a Splunk lookup. Read it with: | inputlookup lab_assets.csv

Enrich every source IP with lab_assets.csv. For each source, give:
- a verdict: malicious, suspicious or benign
- a confidence level
- the evidence for each claim, with the query that shows it
- anything you could not verify

Check the data before you write the detection query.
```

---

## Timeline of tool calls and corrections

| # | Time | Call | Result |
|---|---|---|---|
| 1 | 13:15 | `splunk_get_info` | Not relevant to the task |
| 2 | 13:16 | `\| metadata type=index \| table name, description` — **no `earliest_time`** | Declined. `type=index` is not valid |
| **C1** | 13:16 | **Correction 1:** "Set earliest_time to -30d on every call. `metadata type=index` is not valid. The index is win_dc, start with EventCode=4625." | |
| 3 | 13:16 | `index=win_dc EventCode=4625 \| table _time, EventCode, AccountName, WorkStation, SourceIp, User_Name \| … \| head -100`, `-30d` | `earliest_time` fixed. Guessed field names; negative `head` |
| 4 | 13:18 | Same fields, `head 20` | Same guessed fields |
| 5 | 13:19 | Same fields, plus `eval _raw=""` | Same fields a third time; discarded the raw text that would have shown the real fields. Declined |
| **C2** | 13:19 | **Correction 2:** "These fields don't exist. Run `index=win_dc EventCode=4625 \| head 3 \| table *`." | |
| 6 | 13:20 | `… \| head 3 \| table *` | Followed the instruction |
| 7 | 13:20 | `stats count as attempts by TargetUserName, IpAddress, WorkstationName` | **Correct fields** (`TargetUserName`, `IpAddress`, `WorkstationName`). 30-day totals, no window |
| 8 | 13:21 | Same stats, filtered to 10.0.20.120 after `stats` | Right direction (drill-down on the top source); filter after aggregation |
| 9 | 13:37 | Filter moved into the base search; `where attempts>=10` | More efficient; `>=10` instead of `>10`; still no window, no lookup |
| 10 | 13:40 | `input_type=csv file:///lab_assets.csv` (no `earliest_time`) | **Invented syntax for the lookup**, although the prompt gave `\| inputlookup lab_assets.csv` verbatim. Declined |
| **C3** | 13:40 | **Correction 3:** "Read the lookup exactly like this: `\| inputlookup lab_assets.csv`. The detection must count per account within 5 minutes (`streamstats time_window=5m`)." | |
| 11 | 13:41 | `index=win_dc EventCode=4625 \| inputlookup lab_assets.csv \| streamstats count … by TargetUserName, TimeRange …` | Applied both corrections mechanically: `inputlookup` mid-pipeline, `streamstats` without `time_window`, invented field `TimeRange`. Approved to observe recovery |
| 12 | 13:42 | `inputlookup lab_assets.csv \| earliest_time_to_now() as TimeRange \| join type=inner maxbang=3 [search …]` | After the error, **more invented syntax**: a function that does not exist (`earliest_time_to_now()`), a `join` option that does not exist (`maxbang`), no join field, still no window. Stopped |

> The wall-clock gap between calls 8 and 9 (13:21 → 13:37) was waiting for human approval, not model time. The model's turn took 2m 46s.

---

## What it got right

- **Once shown the data, it used it.** After `table *`, it switched to the real fields and kept them.
- **It found the right sources.** Its interim summary named 10.0.20.120 (many accounts, hundreds of attempts), 10.0.30.101 (WIN-CL02) and 10.0.50.105 (FILE-SRV01) — the same three sources as the ground truth.
- **It drilled down in a sensible order:** overview by source, then the top source, then timing.
- **It followed simple, explicit rules after one reminder** (`earliest_time` on later calls), and never left the Splunk tools (local tools were disabled).

## What it got wrong

- **Rules in the prompt were not enough.** It missed `earliest_time` on the first query and again on the lookup query, despite the rule in the prompt.
- **It repeated the same wrong field names three times** before being told to look at the data, and once removed `_raw` — the one thing that would have shown the real fields.
- **It invented SPL whenever it reached something it didn't know:** `metadata type=index`, `head -100`, `input_type=csv file:///…`, `earliest_time_to_now()`, `maxbang`, `TimeRange`.
- **It did not recover from errors.** After a broken query, the next attempt added more invented syntax instead of simplifying.
- **It judged before enriching.** "10.0.20.120 is aggressively attacking… definitely exceeding 10 failures" — stated before reading the asset inventory, which marks it as the authorized scanner. The same premature attribution Claude made in Eval 02 without context.
- **No detection with a 5-minute window, no lookup, no verdicts** at the stop point.

---

## Scoring across Eval 02 runs

| | 02 — Claude, no context | 02b — Claude, with lookup | 02c — Qwen, noisy prompt | **02d — Qwen, guided** |
|---|---|---|---|---|
| Human corrections | 0 | 0 | 0 (stopped by token limit) | **3** |
| Correct fields | ✅ on its own | ✅ on its own | ❌ | ✅ after correction 2 |
| Time range set | ✅ | ✅ | ❌ (silent 6h default) | ✅ after correction 1 (missed once more later) |
| 5-minute sliding window | ✅ | ✅ | ❌ | ❌ |
| Lookup used | n/a | ✅ | ❌ (`find /` on disk) | ❌ (invented syntax twice) |
| Right sources identified | ✅ | ✅ | ❌ | ✅ |
| Verdicts | 1 of 3 (+1 partial) | **3 of 3** | 0 | 0 |
| Stayed in Splunk tools | ✅ | ✅ | ❌ | ✅ (enforced) |
| Model time | minutes | minutes | 8 min, ended by 32K-token runaway | ≈5 min over 4 turns |

---

## Lessons

1. **Guidance moves a small model forward, but does not carry it to the finish.** Three corrections fixed the time range, the fields and the focus. Correction 3 (lookup + window) produced worse SPL, not better.
2. **"Show me the data" was the most effective correction.** `table *` instantly fixed the field names it had guessed three times. Small models benefit from being shown, not told.
3. **Explicit instructions are not reliably followed.** The exact `inputlookup` command was in the prompt; the model still invented its own syntax. For a small model, the prompt is a suggestion, not a contract.
4. **Error recovery is the real gap.** Claude treated an empty or failed result as information; Qwen treated it as a reason to try a more elaborate guess.
5. **Constraining the agent worked.** Disabling local tools kept this run entirely inside Splunk, with no repeat of the `find /` disk scan from 02c. Least privilege for agents is cheap and effective.
6. **For this task, a 9B local model is a junior analyst who needs a senior next to every query.** That is useful for learning, not for unattended triage.

---

## Evidence

- `../evidence/02d-qwen-transcript.txt` — full `/export` of the session.
- Approval prompts recorded during the run (query text and `earliest_time` per call), summarized in the timeline above.
