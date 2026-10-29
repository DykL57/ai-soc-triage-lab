# AI Eval 01 — Local LLM writing SPL: Brute Force Detection

**Date:** 2026-10-28
**Goal:** Test whether a small local LLM can write a correct Splunk SPL detection, and document where it fails — as a baseline for comparing local vs. cloud models in an AI-assisted SOC workflow.

---

## Environment

| Item | Value |
|---|---|
| Host | Windows workstation — Intel Core Ultra 7 265, 256GB RAM |
| GPU | NVIDIA RTX 5050, 8GB VRAM (~1.8GB already used by the desktop) |
| Runtime | Ollama 0.40.12 (llama.cpp runner) |
| Model | `qwen3.5:9b` (Q4_K_M, ~5.6GB) |
| Target data | `index=win_dc` — Windows Security logs from DC01 in the purple team lab |
| Sourcetype | `XmlWinEventLog` (Universal Forwarder with `renderXml=true`) |

---

## Test case

Detect **more than 10 failed logons (EventCode 4625) for the same account and source IP within any 5-minute sliding window**, and output `account`, `src_ip`, `count`, `first_time`, `last_time`.

### Prompt v1 — no data context

```
Write a Splunk SPL query that detects brute force attempts:
more than 10 failed Windows logons (EventCode 4625) for the same
account within 5 minutes. Index is win_dc. Show the account,
source IP, count, first and last time.
```

### Prompt v2 — with field names and output constraints

```
Write a Splunk SPL query for index=win_dc. Detect more than 10 failed
logons (EventCode=4625) for the same account and source IP within any
5-minute sliding window. Fields available: Account_Name (multivalue,
the 2nd value is the target account), Source_Network_Address.
Output: account, src_ip, count, first_time, last_time.
Return only the SPL and a 2-line explanation.
```

> **Note:** the field names given in prompt v2 turned out to be **wrong for this environment** (see Lab validation). They are the classic `WinEventLog` names; the lab sends `XmlWinEventLog`. The schema context given to the model was itself an unverified assumption.

---

## Results

| Run | Prompt | Context | Thinking | Output tokens | Speed | GPU split | Duration | Result |
|---|---|---|---|---|---|---|---|---|
| 1 | v1 | 8192 | On | 8,121 | 41.7 t/s | 100% GPU | 3m41s | **No answer** — context exhausted mid-reasoning |
| 1b | v1 | 8192 | On (`/set nothink` did not take effect) | 8,108 | 42.4 t/s | 100% GPU | 3m15s | **No answer** — same loop |
| 2 | v2 | 16384 | On | 7,221 | 34.8 t/s | 16% CPU / 84% GPU | 3m33s | Answer produced — **incorrect**; search job fails in Splunk |

### Run 2 output

```spl
index=win_dc EventCode=4625
| eval account = mvindex(Account_Name, 1) | rename Source_Network_Address as src_ip
| timechart span=5m count(*) as count min(_time) as first_time max(_time) as last_time by account, src_ip
| where count > 10
```

---

## Error analysis

| # | Model behavior | Reality | Type |
|---|---|---|---|
| 1 | Stated repeatedly that `streamstats` has no time-based window | `streamstats` supports `time_window=5m` — the correct solution | Confident hallucination |
| 2 | Used `timechart ... by account, src_ip` | `timechart` supports only **one** split-by field; the search job failed in the lab | Invalid syntax |
| 3 | Filtered with `where count > 10` after `timechart` | `timechart` creates one column per split value; the filter does not work as intended | Logic error |
| 4 | Was asked for a sliding window, delivered fixed 5m buckets | Bursts crossing a bucket boundary are missed | Requirement silently changed |
| 5 | Claimed `transaction` outputs `_txn_count` (run 1) | `transaction` outputs `eventcount` and `duration` | Hallucinated field |
| 6 | Guessed field names `SourceIp`, `ClientIpAddress`, `User_Name` (run 1) | In this lab (`XmlWinEventLog`) the fields are `TargetUserName` and `IpAddress` | Guessing without data access |
| 7 | Reasoning looped between `bin`, `transaction` and `stats` for 8K+ tokens | — | Reasoning loop / no stopping criterion |

**What changed with context (v2):** the model used the field names it was given (`mvindex(Account_Name, 1)`, `Source_Network_Address`). It followed the context faithfully — but that context was wrong for this data, so the query would have returned nothing even if the syntax had been valid.

---

## Lab validation

All searches run in Splunk Search & Reporting, time range **Last 30 days**, saved as reports with the `AI-EVAL-01` prefix.

| Step | Report | Result |
|---|---|---|
| 1 | `AI-EVAL-01 - 4625 Field Validation` | Data exists (Oct 3 bursts). `Account_Name` and `Source_Network_Address` are **empty** — sourcetype is `XmlWinEventLog` |
| 1b | `AI-EVAL-01 - 4625 Field Validation` (XML fields) | `SubjectUserName` = `-`, `TargetUserName` and `IpAddress` populated. **`IpAddress` is a duplicated multivalue** (`10.0.20.120` twice) |
| 2 | `AI-EVAL-01 - Brute Force Sliding Window (Reference)` | 32 account / source IP pairs above threshold (see below) |
| 3 | `AI-EVAL-01 - Brute Force (Qwen3.5-9B Output)` | **Search job failed** |

### Findings from step 2

| Source IP | Host | What it looks like | Detail | Verdict |
|---|---|---|---|---|
| `10.0.20.120` | GREENBONE01 (vulnerability scanner) | Password spray / default-credential check | ~30 accounts (`Administrator`, `admin`, `Guest`, `root`, `backup`, `ftpadmin`, `rdpadmin`, ...) in ~46 seconds, 2026-10-03 00:51:53–00:52:39; most accounts hit exactly 50 times, `administrator` 90 | **Benign true positive** — the detection fired correctly on real spray behavior, but the source is an authorized scanner. Confirm it matches a scheduled scan |
| `10.0.50.105` | FILE-SRV01 | Targeted failures on `Administrator` | 12 attempts in ~1.5 minutes, 2026-10-03 15:31:10–15:32:38 | **Open** — needs triage (see below) |
| `10.0.30.101` | WIN-CL02 | Account `WIN-CL02` failing from its own IP | 19 attempts in ~1.7 minutes, 2026-10-03 02:12–02:13 | **Open** — likely machine-account / misconfiguration, needs triage |

### Triage notes

- **GREENBONE01:** the uniform pattern (exactly 50 attempts per account, a fixed username list, sequential accounts) is typical of an automated scanner, not a human. Tuning should exclude it through a lookup of authorized scanners (e.g. `authorized_scanners.csv`) rather than a hard-coded IP, and only within its scan window, so a compromised scanner is still visible.
- **FILE-SRV01:** a server failing as `Administrator` is unusual. Check `SubStatus` (`0xC000006A` wrong password vs. `0xC0000064` unknown user), `LogonType` and `ProcessName` in the same events, and look for a 4624 success from the same source afterwards. Common benign cause: a service, scheduled task or mapped drive with a stale password. FILE-SRV01 also sits in the 10.0.50.0/24 zone with KALI-OPS01, so check whether it was used as a pivot in an attack simulation that day.
- **WIN-CL02:** a machine account failing from its own address usually points to a broken secure channel or a stale computer password with the domain. Check `SubStatus` and `LogonType`.

### Triage results (report `AI-EVAL-01 - Triage FILE-SRV01 and WIN-CL02 Logons`)

**FILE-SRV01 → `Administrator`:** 19 failures over ~22 hours (13:57–15:32 on 10/03, one more on 10/04). All `LogonType 3`, `SubStatus 0xC000006A` (**existing account, wrong password**). Failures arrive in clusters of 3–4 within the same second, the retry pattern of an SMB client re-trying with a cached or typed credential, not the steady rate of a brute-force tool. **No successful `Administrator` logon from 10.0.50.105** in the data. Assessment: most likely a stale or mistyped credential; low severity. To close: check event 4648 (explicit credentials) on FILE-SRV01 to identify the process.

**WIN-CL02 → `WIN-CL02`, then `Administrator`:** 29 failures from 02:12:03 to 02:19:46 on 10/03, all `LogonType 3`, `SubStatus 0xC0000064` (**username does not exist**). The username tried was the computer's own name without `$`. **At 02:20:01, 15 seconds after the last failure, the same host logged on successfully as `Administrator`**, followed by more `Administrator` logons at 02:23, 02:24, 12:28, 22:08 and 07:59 on 10/04. This is the "failures followed by success" pattern. Benign reading: someone typed the hostname as the username, then corrected it to `Administrator`. Malicious reading: an attacker on WIN-CL02 guessing usernames, then authenticating with a valid admin credential. Either way, a domain `Administrator` network logon from a workstation is high-risk in production. **Verdict depends on whether a lateral-movement simulation was run from WIN-CL02 at that time.**

### FILE-SRV01 root cause (reports `AI-EVAL-01 - FILE-SRV01 Data Sources`, `AI-EVAL-01 - FILE-SRV01 Explicit Credential Use 4648`)

FILE-SRV01 sends `index=windows` (classic `WinEventLog`) and `index=sysmon` (`XmlWinEventLog`), so no host access was needed. Note the **format mismatch**: DC01 sends XML (`TargetUserName`), FILE-SRV01 sends classic (`Account_Name`), for the same event IDs. Also noted: ~63.8M Sysmon events from this one server in two months, a candidate for Sysmon config tuning.

4648 events on FILE-SRV01 show a repeating sequence:

| FILE-SRV01 boot (UMFD / DWM / SplunkForwarder start) | `Administrator` interactive logon (`svchost.exe` → localhost) | Failed `Administrator` logons at DC01 |
|---|---|---|
| 10/03 13:59 | 13:56, 13:59 | 13:57, 14:01–14:02 |
| 10/03 15:29 | 15:29 | 15:31–15:32 |
| 10/04 11:56 | 11:54, 11:57 | 12:03 |

Every failure burst at the DC follows an `Administrator` logon on FILE-SRV01 within minutes. **Hypothesis:** an interactive session as `Administrator` on FILE-SRV01 triggers network authentication to DC01 (for example, a persistent mapped drive reconnecting after a reboot) with a password that does not match the DC's `Administrator`, hence `SubStatus 0xC000006A`. 4648 does not show the outbound connection itself (implicit NTLM with the session's own credentials does not generate 4648); Sysmon network events can confirm it.

**Confirmation (report `AI-EVAL-01 - FILE-SRV01 Connections to DC01 During Failures`):** Sysmon EventCode 3 shows SMB (445) connections from FILE-SRV01 to DC01 opened by `System`, the kernel SMB client used for file shares and mapped drives, at 15:31:11, 15:31:21 and 15:31:38. These match the DC failures at 15:31:10, 15:31:20 and 15:31:37 (~1 second clock offset between the hosts). The 15:32:34–38 failures have no new connection because Sysmon logs only new TCP connections; they reused an open SMB session. Before the SMB attempts, `dsregcmd.exe` and `lsass.exe` contacted the DC over LDAP / RPC at 15:30:52, normal post-boot domain activity.

**Verdict: benign — SMB access to DC01 from an `Administrator` session with a mismatched password, after reboots. Severity: informational. Status: closed.** Hygiene recommendations: avoid interactive use of `Administrator`, remove persistent mappings that use it, and use LAPS for unique local admin passwords.

> **Correction (2026-10-29, found by the AI in Eval 02b and verified):** the "persistent mapped drive" hypothesis was wrong. The alerting burst came from a **Zabbix agent deployment**: `FILE-SRV01\Administrator` ran `\\DC01\ZabbixDeploy\Install-Zabbix-Agent2.ps1` manually at 15:31:10 and `net view \\DC01` at 15:31:37, matching the DC failures to the second. The local Administrator's credentials were sent to the DC, where the domain Administrator has a different password (`0xC000006A`). Earlier runs of the same script at 13:59 and 15:29 ran as `SYSTEM` right after boots. Verdict and severity unchanged.

### WIN-CL02 root cause (report `AI-EVAL-01 - WIN-CL02 Process and Network Activity 0210-0225`)

Sysmon on WIN-CL02 shows the session belonged to a **local user named `WIN-CL02`** (`WIN-CL02\WIN-CL02`, same name as the host). That local account does not exist in the domain, which explains `SubStatus 0xC0000064` at the DC.

| Time (10/03) | Activity on WIN-CL02 | At DC01 |
|---|---|---|
| 02:12:55 | `ping DC01` (from PowerShell) | |
| 02:13:00–02:13:06 | PowerShell connects to DC01:445 | failures as `WIN-CL02` (02:12–02:13) |
| 02:13:35 | `net view \\DC01` | failures |
| 02:19:45 | `whoami`, `net use` | |
| 02:19:46 | `dir \\DC01\ZabbixDeploy` | failures (02:19:46) |
| 02:19:51 | `net use \\DC01\ZabbixDeploy /user:LAB\Administrator *` (password typed) | **success as `Administrator` 02:20:01** |
| 02:21:18–02:21:34 | `net use ... /delete` (twice) | |
| 02:23:48 | `net use \\DC01\ZabbixDeploy /user:LAB\Administrator *` | success 02:23:53 |
| 02:24:05 | `powershell -ExecutionPolicy Bypass -File \\DC01\ZabbixDeploy\Install-Zabbix-Agent2.ps1` | success 02:24:09 |
| 02:24:09–02:24:15 | `msiexec /i zabbix_agent2-7.0.31...msi /qn SERVER=10.0.20.121`; Zabbix Agent 2 service installed and started | |

**Verdict: benign — manual deployment of the Zabbix Agent 2 from a share on DC01, authenticated with `LAB\Administrator` after the local account was denied. Severity: informational. Status: closed.**

**Why this case matters:** without context, the same sequence matches common attacker tradecraft: discovery (`net view`, `whoami`), failed logons followed by a domain admin success, `powershell -ExecutionPolicy Bypass` from a remote share, and a silent `msiexec /qn` install of a remote monitoring agent (a tool class attackers also abuse). The telemetry alone cannot separate an admin from an attacker; context (a change record or the admin's confirmation) closes it. This is a good test case for an AI triage agent: does it call it malicious, benign, or ask for the missing context?

### Blast radius: where `Administrator` logs on (report `AI-EVAL-01 - Administrator Successful Logons by Source`)

| Source | Host | LogonType | Count | Range | Assessment |
|---|---|---|---|---|---|
| 10.0.50.111 | WIN-EDR01 | 3 | 2,185 | 10/03 → 10/14 | Expected activity, but a **hygiene finding**: the EDR server appears to use the domain `Administrator` as a service credential. If WIN-EDR01 is compromised, the attacker holds domain admin. Fix: a dedicated, least-privilege service account |
| 10.0.30.100 | WIN-CL01 | 3 | 1,286 | 10/03 → 10/15 | Interactive `LAB\Administrator` session left logged on for 12 days (see below). Benign, but a **tiering violation** |
| 10.0.30.101 | WIN-CL02 | 3 | 8 | 10/03 → 10/04 | Zabbix agent deployment with `LAB\Administrator`; closed as benign |
| 10.0.20.55 | Windows host (VMware Network Adapter VMnet3) | 3, 7, 10 | 6 | 10/03 → 10/04 | Lab admin's own workstation: RDP to the DC (after one failure with the domain name `Lab` typed as the username), SSH to SPLUNK01 as `splunk` and to linux-srv01. Identified from Splunk (`who`, `linux_secure`, DC 4624/4625) and confirmed with `ipconfig`. Benign. Design note: the physical host sits directly on the server zone (VMnet3) |
| 10.0.50.50 | WIN-REDTEAM01 | 3 | 1 | 10/03 13:30 | Authorized red team host; expected test activity |
| `-` | — | 3 | 2 | 10/03 13:17 | No source IP; likely local to the DC |
| 10.0.50.105 | FILE-SRV01 | — | **0** | — | No successful logon. FILE-SRV01 failures closed as **benign, low severity** |

### WIN-CL01 root cause (reports `AI-EVAL-01 - WIN-CL01 Administrator Logon Profile`, `AI-EVAL-01 - WIN-CL01 Processes Running as Administrator`)

From the DC: all 1,286 logons are Kerberos, spread over all 24 hours (~107 per day, roughly every 13 minutes), from 10/03 02:02 to 10/15 04:12. That is a machine-driven rate, not a person typing.

From Sysmon on WIN-CL01:

| Time | Activity as `LAB\Administrator` |
|---|---|
| 10/03 02:02 | Interactive logon: `explorer.exe` starts `vmtoolsd`, `SecurityHealthSystray`, `ctfmon`, `powershell` |
| 10/03 02:02:56 | `powershell.exe` connects to 10.0.20.121:10051 (Zabbix server port), a connectivity test |
| 10/03 02:04:52 | `msiexec.exe` — Zabbix agent install, 20 minutes before the same install on WIN-CL02 |
| 10/03 → 10/15 | OneDrive client syncing to Microsoft cloud IPs, daily `cleanmgr` / `DismHost` maintenance, `CompatTelRunner` telemetry |
| 10/04 02:36 | New logon after a reboot (`runonce`, `ctfmon` again) |
| 10/15 ~04:12 | Activity ends, consistent with the VM being shut down |

**Verdict: benign — the admin logged on interactively as `LAB\Administrator` to install the Zabbix agent and left the session open for 12 days; the session's background activity (Kerberos ticket and policy refreshes) produced the steady logon stream at the DC. Severity: informational. Status: closed.**

**Why it still matters:** a domain admin session left on a workstation keeps its credentials in LSASS memory. Anyone who compromises WIN-CL01 during those 12 days can dump them and own the domain. This violates the tiering model (domain admins log on only to tier 0 systems). The same session also ran OneDrive sync to the internet under a domain admin identity.

`Administrator` was not used for any network logon before 10/03, although DC data exists from 09/29. All usage starts on the day of the attack simulations.

> Query note: `| sort _time` without `0` keeps only the first 10,000 results. The export stopped at exactly 10,000 rows (last event 2026-10-26), so later events were cut. The 10/03–10/04 window is fully covered. Use `sort 0 _time` in future triage searches.

### Data pipeline finding

`IpAddress` is extracted twice per event (two identical values). Possible causes include both XML auto-extraction and a TA or custom extraction producing the same field; to be confirmed with:

```
splunk btool props list XmlWinEventLog --debug
```

Until fixed at the source, the detection deduplicates the field with `mvdedup()`.

---

## Reference solution

> Status: **validated against existing lab data** (2026-10-03 bursts). Boundary-crossing test still pending.

```spl
index=win_dc EventCode=4625
| eval account=TargetUserName, src_ip=mvdedup(IpAddress)
| sort 0 _time
| streamstats time_window=5m count as attempts
    min(_time) as first_time max(_time) as last_time
    by account, src_ip
| where attempts > 10
| stats max(attempts) as count min(first_time) as first_time
    max(last_time) as last_time by account, src_ip
| convert ctime(first_time) ctime(last_time)
```

- `TargetUserName` / `IpAddress` — field names for `XmlWinEventLog`. No `mvindex` needed: the XML format separates Subject and Target into different fields.
- `mvdedup(IpAddress)` — works around the duplicated extraction.
- `sort 0 _time` — `time_window` requires events in time order.

> The first draft of this reference solution (written with a cloud model, Claude) used `Account_Name` / `Source_Network_Address` — the same unverified-schema mistake the local model made. It was caught only by running step 1 against real data.

---

## Lessons

1. **Small local models are fast but unreliable for SPL.** ~42 t/s fully on GPU, but no working answer in three runs.
2. **Unbounded thinking is a failure mode.** Two of three runs spent the entire context reasoning and never answered. Production use needs token / reasoning limits.
3. **Without schema access, models invent field names — and so do people.** The local model guessed, the cloud-drafted reference guessed, and the "context" given in prompt v2 was a guess. Only querying the data settled it. This is the strongest argument for giving an agent live tool access (MCP) to the SIEM.
4. **The most dangerous errors are the confident ones.** The final answer did not mention that it had replaced a sliding window with fixed buckets. An analyst who trusts the output would deploy a detection with a blind spot.
5. **Validate against data before trusting any detection.** A 4-line field check (step 1) caught an error that code review alone would have missed.
6. **VRAM is the constraint.** On an 8GB card that also drives the display, raising context from 8K to 16K pushed 16% of the model to CPU and cut speed by ~18%.

---

## Next steps

- [ ] Re-run step 2 with `mvdedup(IpAddress)` and compare counts to the first run (did the duplicate extraction affect them?).
- [ ] Confirm the cause of the duplicated `IpAddress` with `btool`.
- [ ] Confirm the GREENBONE01 burst matches a scheduled scan; add an `authorized_scanners` lookup and scope the exclusion to scan windows.
- [x] Triage FILE-SRV01 → `Administrator` — closed: SMB credential mismatch after reboots.
- [x] Triage WIN-CL02 — closed: Zabbix agent deployment.
- [x] Identify 10.0.20.55 — the Windows host (VMnet3 adapter).
- [x] Explain WIN-CL01's 1,286 `Administrator` logons — closed: admin session left open for 12 days.
- [ ] Hygiene: service account for WIN-EDR01, no domain admin logons on workstations, LAPS, review Sysmon volume on FILE-SRV01.
- [ ] AI triage comparison: give the same evidence to a local and a cloud model and compare their verdicts, especially WIN-CL02 (admin activity that looks like attacker tradecraft).
- [ ] Boundary-crossing test: generate a burst that straddles a 5-minute boundary (e.g. 6 attempts at hh:04:50, 6 at hh:05:10) and show that the sliding window catches it while fixed `bin span=5m` buckets do not.
- [ ] Re-run with thinking disabled: `ollama run qwen3.5:9b --think=false --verbose`.
- [ ] Run the same prompts against a cloud model (Claude) and compare.
- [ ] Test a larger MoE model using system RAM (e.g. `qwen3.6:35b-a3b`).
- [ ] Give the agent live schema access to Splunk via MCP and re-test prompt v1.
