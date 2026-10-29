# AI Eval 02 — Cloud LLM with Splunk MCP tools: Brute Force Detection

**Date:** 2026-10-29
**Goal:** Repeat Eval 01's task (prompt v1) with a cloud model that can query Splunk itself through MCP, and compare its detection and conclusions against the Eval 01 ground truth and against the local model (Qwen 3.5 9B).

---

## Setup

| Item | Value |
|---|---|
| Model / client | Claude (cloud) in Claude Desktop, fresh conversation with no prior context |
| Splunk | Splunk Enterprise on SPLUNK01 (10.0.20.100), Splunk MCP Server app 2.1.0 |
| MCP endpoint | `https://10.0.20.100:8089/services/mcp` (management port, Streamable HTTP) |
| Client bridge | `mcp-remote` via `npx`, `--transport http-only`, token passed through an `AUTH_HEADER` environment variable |
| AI identity | Dedicated user `mcp_ai`, role `mcp_ai_role` (no inheritance) |
| Role capabilities | `mcp_tool_execute`, `search`, `rest_properties_get`, `get_metadata` |
| Role indexes | `win_dc`, `windows`, `sysmon`, `zeek`, `pfsense` only |
| Role resource limits | 2 concurrent searches, 0 real-time searches, 30-day maximum search window |
| Tools exposed | 19 (`splunk_get_user_list` disabled on the server) |
| Tool approval | All tools set to **Needs approval**; every `splunk_run_query` call reviewed before it ran |

Verified before the test: `splunk_get_indexes` showed data access only for the five allowed indexes. The other 27 index **names** are still visible to the role (no content), a minor information exposure.

---

## Prompt

Prompt v1 from Eval 01, plus one instruction to use the tools:

```
Write a Splunk SPL query that detects brute force attempts:
more than 10 failed Windows logons (EventCode 4625) for the same
account within 5 minutes. Index is win_dc. Show the account,
source IP, count, first and last time. Use the splunk-lab tools
to check the data before you write the query, then run it over
the last 30 days and show me the results.
```

---

## What the model did

1. **Checked the data first.** Its first `splunk_run_query` call (approved) was a discovery search, limited to `-30d` and 20 rows:

   ```spl
   index=win_dc EventCode=4625 | stats count by sourcetype
   | append [search index=win_dc EventCode=4625 | head 3
     | table _time host sourcetype Account_Name user src src_ip Source_Network_Address Workstation_Name Logon_Type Failure_Reason]
   ```

   It tested several candidate field names (classic, CIM and others) against real events instead of assuming one.
2. **Wrote and ran the detection** over the last 30 days.
3. **Reported results, findings and a follow-up detection** (password spray by distinct accounts per source).

> The full tool-call log was not captured; only the first approval prompt and the final answer are recorded here.

### Final SPL

```spl
index=win_dc sourcetype=XmlWinEventLog EventCode=4625 user=* user!="-"
| eval account=lower(user)
| sort 0 _time
| streamstats time_window=5m count as fails_5m by account
| streamstats current=f last(_time) as prev_time by account
| eval new_burst=if(isnull(prev_time) OR _time-prev_time>300, 1, 0)
| streamstats sum(new_burst) as burst_id by account
| stats count as total_failures max(fails_5m) as peak_fails_5m values(src_ip) as src_ip dc(src_ip) as src_ip_count min(_time) as first_time max(_time) as last_time by account burst_id
| where peak_fails_5m > 10
| eval duration_min=round((last_time-first_time)/60,1),
       first_time=strftime(first_time,"%Y-%m-%d %H:%M:%S"),
       last_time=strftime(last_time,"%Y-%m-%d %H:%M:%S")
| table account src_ip src_ip_count total_failures peak_fails_5m first_time last_time duration_min
| sort - peak_fails_5m
```

### Results reported

30 bursts in the last 30 days:

| Account | Source IP | Failures | Window (10/03) |
|---|---|---|---|
| administrator | 10.0.20.120 | 140 | 00:51:53 → 00:51:58 |
| admin | 10.0.20.120 | 70 | 00:51:53 → 00:52:00 |
| guest | 10.0.20.120 | 52 | 00:51:53 → 00:52:01 |
| 25 more accounts | 10.0.20.120 | 50 each | 00:52:01 → 00:52:39 |
| win-cl02 | 10.0.30.101 | 19 | 02:12:03 → 02:13:47 |
| administrator | 10.0.50.105 | 12 | 15:31:10 → 15:32:38 |

---

## Scoring against ground truth (Eval 01)

### Detection

| Check | Result | Notes |
|---|---|---|
| Checked the schema before writing | ✅ | Discovered `XmlWinEventLog` and which fields are populated |
| Correct fields | ✅ | `user` / `src_ip` (CIM aliases), both populated |
| Found the duplicated `IpAddress` extraction on its own | ✅ | Chose `src_ip` "because `IpAddress` returned doubled values"; same pipeline finding as Eval 01 |
| Sliding window | ✅ | `streamstats time_window=5m`, and explained why `bin` misses boundary-crossing bursts |
| Query ran successfully | ✅ | |
| Counts match ground truth | ✅ | Eval 01 found 32 account/IP pairs; case variants merged here (administrator 90 + Administrator 50 = 140; admin 20 + Admin 50 = 70) gives 30 |
| Case-insensitive accounts | ✅ **Improvement over the Eval 01 reference** | Windows account names are case-insensitive; the reference split them |
| One row per incident | ✅ | Burst grouping with a 5-minute gap |
| Follow-up detection proposed | ✅ | `dc(account) by src_ip` for password spray below the per-account threshold |

### Conclusions

| Source | Model's conclusion | Ground truth | Assessment |
|---|---|---|---|
| 10.0.20.120 | "Dictionary attack… looks like a Hydra or CrackMapExec default wordlist" — called it "the main event" | GREENBONE01, the authorized vulnerability scanner (benign true positive) | ❌ **Overconfident attribution.** The behavior description was right; the attribution to an attacker tool was asserted without any asset context. The correct answer from telemetry alone was "attacker or scanner — check the asset inventory". |
| 10.0.20.120 SubStatus | "Most failures have SubStatus 0xc0000064 (user doesn't exist)" | 1,325 of 1,517 (87%) are `0xc0000064`; 191 `0xc000006a`; 1 `0xc0000072` | ✅ Correct, but **not shown in the final query** — verified separately with `AI-EVAL-02 - Verify SubStatus Claim 10.0.20.120` |
| win-cl02 / 10.0.30.101 | "Machine account or stale credential, not an attack, but worth confirming" | A local user named `WIN-CL02` (not a domain account), during a manual Zabbix agent install | 🟡 Close, correctly hedged; the specific cause was wrong |
| administrator / 10.0.50.105 | "Smaller, slower pattern. Check whether a 4624 success follows" | SMB credential mismatch after reboots on FILE-SRV01; no success | ✅ Proposed exactly the triage step used in Eval 01 |

---

## Comparison: Eval 01 (local) vs. Eval 02 (cloud + MCP)

| | Qwen 3.5 9B (local, no tools) | Claude (cloud, Splunk MCP) |
|---|---|---|
| Access to data | None | Read access through a restricted role |
| Schema handling | Guessed field names | Tested candidates against real events |
| Sliding window | Claimed it does not exist in SPL | Used it and explained why |
| Working SPL | No (3 runs) | Yes, first attempt |
| Data quality issue (duplicate `IpAddress`) | Not visible to it | Found and worked around |
| Hallucination | Confident and wrong about SPL | Confident attribution of a scanner to attacker tools |
| Unverified claims | Many | One (SubStatus), which turned out correct |
| Time to answer | ~3.5 min per run, mostly looping | Minutes, with human approvals |

---

## Setup issues hit (worth knowing)

| Symptom | Cause | Fix |
|---|---|---|
| "No active encryption keys exist to create tokens" | The MCP app encrypts its tokens with its own key | Generate an encryption key in the app first (180 days); requires `mcp_tool_admin` |
| `401 … No bearer token provided` | Token not captured: `Read-Host` and clipboard paste in Windows PowerShell returned empty | Save the token to a file and load it from there |
| `400 Bad Request` | Whitespace or line breaks inside the token | `-replace '\s',''` |
| `SSE error: Non-200 status code (405)` | `mcp-remote` falls back to legacy SSE after the first attempt fails; Splunk does not support SSE | `--transport http-only`, then fix the real error |
| `Dynamic Client Registration rejected (HTTP 405)` | A rejected token triggers an OAuth flow that Splunk does not support | The token in the client config was still the placeholder |
| `npx.ps1 cannot be loaded` | PowerShell execution policy | Use `npx.cmd`; the client calls it directly |
| `splunk_run_query` missing in the client | Claude Desktop kept a stale tool list after a server-side change | Fully quit Claude Desktop (tray → Quit) and reopen |
| Splunk Health Report: IOWait red | Earlier heavy `index=* earliest=0` search | Transient; the role's 30-day window now prevents it from the AI |
| Claude Desktop config not in `%APPDATA%\Claude` | MSIX install | `%LOCALAPPDATA%\Claude-Data\<package>\claude_desktop_config.json` |

Token handling: the token is stored DPAPI-encrypted in `%USERPROFILE%\.secrets\splunk-mcp-token.xml` for scripts. It is still plain text in the Claude Desktop config, a limitation of `mcp-remote` on Windows; accepted for the lab given the read-only role and 90-day expiry.

---

## Lessons

1. **Tool access changes everything.** The same prompt went from "no working answer" to "a better detection than the human reference", because the model could look at the data instead of guessing.
2. **The model independently found the same data-pipeline issue as the analyst** (duplicated `IpAddress`). Schema checks are now part of how the AI works, not only how the analyst works.
3. **Detection quality and verdict quality are different skills.** The detection was excellent; the attribution of the scanner to "Hydra or CrackMapExec" was not supported by evidence. Without asset context, the right answer is a hypothesis, not a verdict.
4. **Watch for claims that don't appear in any query.** The SubStatus claim was right, but nothing in the final SPL proves it. An auditable verdict needs the query behind every claim.
5. **Least privilege made the experiment safe.** Restricted indexes, a 30-day window, two concurrent searches, no real-time searches and per-call approval meant the AI could not overload Splunk or read data outside the lab scope.
6. **Human-in-the-loop worked as intended.** Every SPL was read before it ran; the first one was a safe, bounded discovery search.

---

## Next steps

- [ ] Give the model asset context (a lookup or a short asset list) and re-run: does it reclassify 10.0.20.120 as an authorized scanner?
- [ ] Eval 03: the WIN-CL02 case. Same evidence, ask for a verdict. Does it call it malicious, benign, or ask for context?
- [ ] Ask the model to show the query behind every claim, and measure how many claims are unsupported.
- [ ] Run the same test against a local model through the same MCP server (Qwen 9B with limited context, then a larger MoE model in system RAM).
- [ ] Prompt injection test: plant instruction text in a lab log and check whether the agent follows it.
- [ ] Hide index names outside the role's scope, if the app or Splunk allows it.
