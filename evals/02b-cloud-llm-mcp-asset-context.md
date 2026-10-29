# AI Eval 02b — Same investigation, with asset context

**Date:** 2026-10-29
**Goal:** Repeat Eval 02 with an asset inventory available as a Splunk lookup, and ask for a verdict, a confidence level, the query behind each claim, and what could not be verified. Does context fix the verdict error from Eval 02 (scanner labeled as "Hydra or CrackMapExec")?

---

## Setup

Same as Eval 02 (Claude in Claude Desktop, fresh conversation, Splunk MCP Server 2.1.0, `mcp_ai` with `mcp_ai_role`, every `splunk_run_query` approved by hand), plus:

| Item | Value |
|---|---|
| Asset inventory | `lab_assets.csv` in the `search` app, read-only for `mcp_ai_role` |
| Columns | `ip, hostname, zone, subnet, role, authorized_activity` |
| Rows | 10 lab hosts; `authorized_activity` set for GREENBONE01 (vulnerability scanning incl. default-credential checks), WIN-REDTEAM01 and KALI-OPS01 (attack simulation), and the admin workstation |

### Prompt

```
Investigate brute force activity in index=win_dc over the last 30 days:
more than 10 failed Windows logons (EventCode 4625) for the same account
within 5 minutes. Use the splunk-lab tools.

Our asset inventory is the lookup lab_assets.csv. Enrich every source IP
with it.

For each source, give:
- a verdict: malicious, suspicious or benign
- a confidence level
- the evidence for each claim, with the query that shows it
- anything you could not verify

Check the data before you write the detection query.
```

---

## What the model did

1. Read the lookup and checked 4625 field coverage, including 6 events with no user.
2. Ran the detection, now aggregated **per source IP** and enriched with the lookup.
3. For each of the three sources, checked for successful logons (4624) and lockouts.
4. Went to **Sysmon** on the source hosts to find the process behind the failures, without being asked.
5. Looked for **independent evidence** for the scanner verdict in pfSense, because "the Greenbone verdict rests on the inventory alone".

### Verdicts

| Source | Host | Model verdict | Confidence | Ground truth (Eval 01) | Match |
|---|---|---|---|---|---|
| 10.0.20.120 | GREENBONE01 | Benign (authorized scan) | High, "but it rests on the inventory" | Benign true positive | ✅ |
| 10.0.30.101 | WIN-CL02 | Benign (admin deploying Zabbix) | High | Benign: manual Zabbix agent install | ✅ |
| 10.0.50.105 | FILE-SRV01 | Benign (admin deploying Zabbix) | Medium-high | Benign: SMB credential mismatch | ✅ verdict; root cause refined (below) |

**Eval 02 → 02b: the scanner went from "dictionary attack, Hydra or CrackMapExec" to "benign, authorized scan", and the model still said what that verdict depends on.**

---

## What it got right that the human ground truth did not have

| Finding | Detail | Status |
|---|---|---|
| Corroborating evidence for the scanner | pfSense: 25,181 connections to 3,748 distinct ports from 10.0.20.120 between 00:27 and 01:36 on 10/03, consistent with a full Greenbone scan. The verdict no longer rests on the inventory alone | New evidence |
| WIN-CL02 failures come from a **local** account | `WIN-CL02\WIN-CL02` passed to the DC, where it does not exist (`0xc0000064`) — "a credential mismatch, not guessing" | Matches Eval 01 |
| FILE-SRV01 root cause | The local `FILE-SRV01\Administrator` ran the Zabbix install script from `\\DC01\ZabbixDeploy`; `net view \\DC01` at 15:31:37 falls inside the alert burst; the agent reached the Zabbix server on 10/04 | **Corrects Eval 01**, which concluded "SMB access with a mismatched password, likely a mapped drive". Verified: the alerting burst matches a manual script run at 15:31:10 and `net view` at 15:31:37 to the second (see 1b for the actor detail) |
| No lockouts | No 4740 in 30 days despite 140 wrong `administrator` passwords; RID-500 Administrator is exempt from lockout | Matches the earlier lab README finding |
| Inventory gaps | Zabbix server 10.0.20.121 missing from `lab_assets.csv`; a file server listed in "Zone 5 (attack simulation)" | Both correct. The zone label was written by the eval author, not by the lab owner |
| Tuning | Suppress the scanner only during scheduled scan windows, or by role after the lookup | Same recommendation as Eval 01 |

---

## Errors

### 1. WIN-CL02 timeline built from an aggregated query

The model's narrative:

| Model said | Sysmon per event (Eval 01) |
|---|---|
| 02:11:46: runs `powershell -ExecutionPolicy Bypass -File \\DC01\ZabbixDeploy\Install-Zabbix-Agent2.ps1` | The Bypass script ran at **02:24:05**, after the domain credentials were entered |
| 02:13:35: `net use \\DC01\ZabbixDeploy /user:LAB\Administrator *` | 02:13:35 was `net view \\DC01`; the `net use … /user:LAB\Administrator` came at **02:19:51** |
| 19 failures, 02:12–02:13 | 29 failures, 02:12:03–02:19:46 (19 in the first burst) |

**Cause:** its evidence query was `stats min(_time) as first values(CommandLine) as cmd by EventCode Image`. That returns **one** time per executable (the first `powershell.exe`, the first `net.exe`) next to **all** of that executable's command lines. The model then read the first time as the time of each command. The verdict stayed right, but the timeline was wrong, and the query it cited as evidence cannot show what it claimed.

> **Verified** with `AI-EVAL-02B - Verify WIN-CL02 Timeline (per event)`: 02:11:46 is a plain `powershell.exe` opened by the user (parent `RuntimeBroker.exe`); 02:13:35 is `net view \\DC01`; `net use … /user:LAB\Administrator *` at 02:19:51 and again at 02:23:48; the Bypass script at 02:24:05. The model's timeline was wrong exactly as predicted from its query.

### 1b. FILE-SRV01: right mechanism, wrong actor for two of the runs

> **Verified** with `AI-EVAL-02B - Verify FILE-SRV01 Zabbix Claim`:

| Time (10/03) | User | Activity |
|---|---|---|
| 13:59:28 | `NT AUTHORITY\SYSTEM` | `Install-Zabbix-Agent2.ps1` from `\\DC01\ZabbixDeploy`, right after a boot |
| 15:29:40 | `NT AUTHORITY\SYSTEM` | Same script, right after a boot |
| **15:31:10** | **`FILE-SRV01\Administrator`** | Same script, run manually — **first failure at the DC: 15:31:10** |
| **15:31:37** | **`FILE-SRV01\Administrator`** | `net view \\DC01` — **DC failure at 15:31:37** |
| 15:34–15:39 | `NT AUTHORITY\SYSTEM` | SMB access tests and debug runs writing to `C:\Temp\Zabbix-*.txt` |

The model said the local Administrator ran the script at 13:56 and 15:29; those two runs were `SYSTEM`. The run that matches the alert burst was the manual one by `FILE-SRV01\Administrator` at 15:31:10, to the second. The mechanism the model proposed (local Administrator credentials passed to the DC's domain Administrator) is confirmed for the alerting burst. The 13:57–14:02 failures are still not tied to a specific process.

### 2. Counts slightly off

1,512 failures from 10.0.20.120 vs. 1,517 in the SubStatus check, and "19 failures" for WIN-CL02 (the burst, not the full sequence). Small, but an analyst would quote these numbers.

---

## Scoring

| Dimension | Eval 02 (no context) | Eval 02b (with lookup) |
|---|---|---|
| Detection | ✅ | ✅ (per-source rollup, enriched) |
| Verdicts correct | 1 of 3 (+1 partial) | **3 of 3** |
| Confidence stated and calibrated | Not asked | ✅ Lower for FILE-SRV01, with the reason |
| Query behind each claim | Missing for SubStatus | ✅ For every section |
| "Could not verify" list | Not asked | ✅ Specific and correct (no change ticket, no Greenbone task logs, no MAC/host fingerprint, lockout policy not readable) |
| Went beyond the prompt | Proposed a spray detection | Pivoted to Sysmon and pfSense for corroboration |
| Factual errors | Attribution to attacker tools | Timeline built from an aggregated query |

---

## Lessons

1. **Context fixed the verdict.** One lookup turned "dictionary attack by Hydra/CrackMapExec" into "authorized scanner". The model did not just accept the inventory; it found independent evidence in pfSense and said the verdict rests on the inventory.
2. **Asking for evidence and "could not verify" changed the behavior.** Every claim came with a query and the gaps were named. Prompt design is part of the control.
3. **The AI improved the ground truth.** On FILE-SRV01 it found the actual activity (the Zabbix script from the DC share) where the human investigation stopped at "probably a mapped drive". An eval must allow for the reference being wrong.
4. **The cited query must be able to prove the claim.** The WIN-CL02 timeline looked precise but came from `min(_time)` + `values()` per executable. A reviewer who only checks "is there a query" would miss it; one who reads the query sees it cannot show per-command times.
5. **An inventory is a security control, and it has bugs too.** The model found a missing host and a mislabeled zone.

---

## Next steps

- [x] Run `AI-EVAL-02B - Verify WIN-CL02 Timeline (per event)` and `AI-EVAL-02B - Verify FILE-SRV01 Zabbix Claim`.
- [x] Update Eval 01 ground truth for FILE-SRV01.
- [x] Fill in the Zabbix server's hostname (ZABBIX01, 10.0.20.121).
- [ ] Upload the updated `lab_assets.csv` to Splunk (adds ZABBIX01, removes the invented "attack simulation" zone label).
- [ ] Same prompt through Claude Code backed by local Qwen 3.5 9B via Ollama (same client type, same tools, only the model changes).
- [ ] Prompt injection test.
