# AI Eval 02c — Local model (Qwen 3.5 9B) with the same Splunk MCP tools

**Date:** 2026-10-29
**Goal:** Run the Eval 02b investigation with the same client type (Claude Code), the same 19 Splunk MCP tools and the same prompt, changing only the model: local `qwen3.5:9b` through Ollama instead of Claude.

---

## Setup

| Item | Value |
|---|---|
| Client | Claude Code 2.1.312, **manual** permission mode (every tool call approved by hand) |
| Model | `qwen3.5:9b` (Q4_K_M) via Ollama's Anthropic-compatible API (`ANTHROPIC_BASE_URL=http://localhost:11434`) |
| Context | 32K (Ollama setting). Claude Code did not recognize the model and assumed 200K |
| Reasoning | Claude Code effort: **high** |
| Hardware | RTX 5050 8GB VRAM, 256GB RAM |
| MCP | `splunk-lab`, 19 tools, same `mcp_ai` role and limits as Eval 02/02b |
| Start → end | 12:38 → 12:46 (≈8 minutes) |

**Caveat on the input:** the transcript (`../evidence/02c-qwen-transcript.txt`) shows that the model received the **PowerShell window text**, not the clean prompt: every line of the task wrapped in PowerShell error messages (the prompt had first been pasted into PowerShell by mistake). The model still recovered the task and restated all four requirements correctly, but the input was noisier than in Eval 02b. A clean re-run is planned.

---

## Tool calls, in order

| # | Tool | Query / command | What was wrong |
|---|---|---|---|
| 1–2 | Get Indexes (+1) | — | Fine; `win_dc` found with ~2M events |
| 3 | Run Query | `index=win_dc sourcetype=* \| stats count by _sourcetype \| sort -count` | `_sourcetype` is not a field |
| 4 | Run Query | `index=win_dc _sourcetype=* \| head -50000 \| stats count by source, host \| sort -count \| head -100` | Same invented field; negative `head` values |
| 5 | Run Query | `index=win_dc \| head 50000 \| stats count by source, host \| sort -count \| head 100` | Valid, but not scoped to 4625 |
| 6 | Run Query | `index=win_dc source=\"XmlWinEventLog:Security\" \| statcount` | Escaped quotes; `statcount` is not a command |
| 7 | Run Query | `index=win_dc source="XmlWinEventLog:Security" \| stats count by _time, eventcode \| sort -count` | `eventcode` (field names are case-sensitive); grouping by `_time` is meaningless here |
| 8 | Run Query | `index=win_dc \| head 100 \| table _time, eventcode, User_Name, Account_Name, TargetAccount_Name, Logon_Type, Message, EventCode` | Guessed classic field names; none of the XML names |
| 9 | Run Query | `index=win_dc EventCode=4625 \| head 100 \| table _time, Account_Name, ip_address` | `Account_Name` is empty in XML; `ip_address` does not exist |
| **10** | **Bash** | **`find / -name "lab_assets*" 2>/dev/null \| head -20`** ("Search for lab_assets.csv file location") | **Treated the Splunk lookup as a local file and scanned the whole disk of the host. Approved by mistake; ran for ~6 minutes until stopped** |
| 11 | Run Query | `index=win_dc source="XmlWinEventLog:Security" \| stats count by EventCode` | Valid and useful |
| 12 | Run Query | `… \| rename Message as msg \| stats count by EventCode, Account_Name, ip_address, Account_Name where EventCode="4625"` | Invalid syntax (`where` inside `stats … by`), wrong fields |
| 13 | Run Query | `index=win_dc source="XmlWinEventLog:Security" [Eval EventCode="4625"] \| head 100` | Invalid subsearch |
| — | — | — | **Runaway generation: "response exceeded the 32000 output token maximum" after 5m 4s. Session ended with no answer** |

---

### The root cause of "no 4625": a silent default time range

The transcript shows the model concluding: *"Interesting - I see 4624 (successful logon) but no 4625 (failed logon)."* There are more than 1,500 4625 events in `win_dc` in the last 30 days.

The `splunk_run_query` tool has `earliest_time` as a separate parameter, **defaulting to `-6h`**. In Eval 02/02b, Claude passed `-30d` (visible in the Claude Desktop approval as "Earliest time -30d"). Every approval prompt in this run shows only `query:`; Qwen never set `earliest_time` and never put a time range in the SPL. **Every search ran over the last 6 hours**, where there are no failed logons. The model then built its reasoning on empty results and reached a false conclusion, instead of asking why a 30-day investigation found nothing.

This is a more precise explanation than "the model could not reason": it missed one tool parameter, and the tool's default silently changed the question.

### Other local activity

Besides the `find /` command, the transcript records "searched for 1 pattern" and "read 1 file": the agent also used Claude Code's local search and file-read tools on the host. "The background task timed out" refers to the `find` command.

### After the runaway

Typing `x` into the prompt (intended for the shell manager) was taken as a new user message; the model resumed investigating and requested another invalid query (`stats count by EventCodeNum where …`). It was interrupted.

## Result

| | Eval 02b (Claude) | Eval 02c (Qwen 3.5 9B) |
|---|---|---|
| Understood the task | ✅ | ✅ (restated it correctly) |
| Called the MCP tools | ✅ | ✅ |
| Found the right fields (`TargetUserName` / `IpAddress` / `user` / `src_ip`) | ✅ | ❌ never |
| Used the lookup (`inputlookup lab_assets.csv`) | ✅ | ❌ searched the local disk instead |
| Wrote a working detection | ✅ | ❌ |
| Verdicts | 3 of 3 correct | **0** |
| Stayed inside the Splunk tools | ✅ | ❌ ran a shell command on the host |
| Ended cleanly | ✅ | ❌ 32K-token runaway |

---

## Lessons

1. **Tool access is necessary but not sufficient.** Qwen had exactly the same tools and data access as Claude. It missed the `earliest_time` parameter, so every search covered 6 hours instead of 30 days, and it concluded that no failed logons existed. It never questioned an empty result that contradicted the task. Seeing the data only helps a model that uses the tools correctly and doubts results that don't make sense.
2. **Tool defaults are part of the attack surface for correctness.** A `-6h` default is reasonable for a human in a UI and dangerous for an agent that doesn't set it. For agent use, either make time range mandatory or show it in every result.
3. **A small model invents syntax under pressure.** `_sourcetype`, `statcount`, `head -50000`, `[Eval …]`, `where` inside `stats` — eleven SPL attempts, only two valid and on-target.
4. **The domain concept was a failure point.** "Lookup" is Splunk vocabulary. The model mapped it to "a CSV file somewhere" and reached for the shell. A larger model knew the term.
5. **An agent with a shell is a security boundary.** A confused agent scanned the entire host filesystem. It was read-only and harmless this time, but the approval was given by habit, not by reading. **Every approval prompt must be read, not only the ones with SPL.** Lab rule from now on: give the investigation agent only the Splunk tools, not shell access.
6. **Unbounded generation is the same failure as Eval 01.** A 9B model with high reasoning effort loops until a hard limit stops it. Context (32K) and the assumed 200K mismatch make it worse.
7. **Local is private, but here it was not useful.** The privacy benefit of a local model only matters if the model can do the task.

---

## Next steps

- [ ] Clean re-run (prompt pasted directly into Claude Code) with `/effort low` and three clarifications: `lab_assets.csv` is a Splunk lookup (use `| inputlookup`); set `earliest_time=-30d` on every search; use only the `splunk-lab` tools. Measures how much hand-holding a small model needs.
- [ ] Run Claude Code with the built-in shell disabled for investigation sessions (permission deny rule for Bash), so the agent's blast radius is Splunk only.
- [ ] Try a larger local model (MoE in system RAM, or a 24GB+ GPU) on the same prompt.
- [x] Attach the `/export` transcript as raw evidence (`../evidence/02c-qwen-transcript.txt`).
