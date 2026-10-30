I'll inspect the lab data for each detection first, then write the three rules and a priority ranking.

Run key data is clean: one malicious write (reg.exe, 09:21:30) and two legitimate writers (Edge, OneDrive). Now the 4688 discovery activity.

The 4688 data is XML-rendered, so the field names are `NewProcessName`, `CommandLine`, `SubjectUserName`, and `MandatoryLabel`, not the classic `New_Process_Name`. Re-running with the right fields.

Fixed 10-minute bins split bob's activity across the 09:10/09:20 boundary, which would have weakened the alert. I'll test a sliding window, plus scoring for domain-scope command lines.

Confirmed: Sysmon has no `arp.exe` and no `nltest /trusted_domains`, while 4688 has both. One more step: validating the final Run-key rule against the 7-day data.

Both rules below were tested against the last 7 days of lab data (Oct 23–30). Each one fires on the bob.user activity and nothing else.

## 1. Registry Run key persistence (T1547.001)

**What the data shows:** There were 6 Run/RunOnce writes in 7 days. Five came from legitimate writers: Edge (`MicrosoftEdgeAutoLaunch_*`) and OneDriveSetup.exe (RunOnce cleanup entries). One was malicious: `reg.exe` wrote `Run\Atomic Red Team` at 09:21:30. HKCU writes show up as `HKU\<SID>\...`, not `HKCU\...`, so a filter on `HKCU*` alone would miss them.

**Title: `DET - Registry Run Key Persistence (T1547.001)`**
```spl
index=sysmon EventCode=13 (TargetObject="*\\CurrentVersion\\Run\\*" OR TargetObject="*\\CurrentVersion\\RunOnce\\*")
| eval reg_value=mvindex(split(TargetObject,"\\"),-1)
| eval hive=case(match(TargetObject,"^(HKU|HKCU)"),"HKCU", match(TargetObject,"^HKLM"),"HKLM", true(),"other")
| where NOT (
    (match(Image,"(?i)^C:\\\\Program Files( \(x86\))?\\\\Microsoft\\\\Edge\\\\Application\\\\msedge\.exe$") AND match(reg_value,"^MicrosoftEdgeAutoLaunch_"))
    OR (match(Image,"(?i)^C:\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\(Update\\\\)?OneDrive(Setup)?\.exe$") AND match(Details,"(?i)\\\\Microsoft\\\\OneDrive\\\\"))
  )
| eval lolbin_writer=if(match(Image,"(?i)\\\\(reg|powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$"),1,0)
| eval risky_payload=if(match(Details,"(?i)\\\\(AppData|Temp|Users\\\\Public|ProgramData)\\\\|powershell|mshta|rundll32|regsvr32|https?://|-enc"),1,0)
| eval severity=case(lolbin_writer=1 OR risky_payload=1,"high", hive="HKLM","medium", true(),"low")
| table _time host User hive Image reg_value Details severity
```
- **Keys on:** `TargetObject`, `Image`, `Details`, and the derived `reg_value` and `hive`.
- **Threshold:** It alerts on any single event, because persistence is a one-shot action and one write is enough. Severity tells you how urgent each alert is:
  - High: written by a LOLBin (reg.exe, PowerShell, cmd and similar), or the payload looks risky (user-writable path, script host, URL).
  - Medium: any HKLM write.
  - Low: any other HKCU write.
- **False positives and tuning:**
  - Software installers and updaters will trigger it: Teams, Zoom, Spotify, Discord, vendor update agents.
  - Write each exclusion as an exact Image path plus a value-name or payload pattern, the way Edge and OneDrive are written above. Never exclude on Image path alone.
  - The OneDrive binary lives in AppData, which the user can write to. A Image-only exclusion there would let malware dropped at that path go silent. That's why that exclusion also requires the payload to point at `\Microsoft\OneDrive\`.
  - Once you have more exclusions, move them into a lookup.
  - Schedule every 5 minutes. If low-severity HKCU alerts get noisy, route them to a daily report instead of paging on them.
- **MITRE:** T1547.001 (Registry Run Keys / Startup Folder).

## 2. Low-volume domain recon by a non-privileged user (T1087.002 / T1069.002 / T1482)

**What the data shows:**
- **Field names:** 4688 events here are XML-rendered. The fields are `NewProcessName`, `CommandLine`, `SubjectUserName` and `MandatoryLabel`, not `New_Process_Name` and `Process_Command_Line`. A first draft using the classic names returned nothing.
- **Integrity level:** bob.user ran at Medium integrity (`S-1-16-8192`). Administrator ran at High (`S-1-16-12288`).
- **whoami noise:** bob's session had 14+ bare `whoami.exe` calls from PowerShell. These look like test-harness noise, so the rule counts distinct tools rather than total executions.
- **Fixed bins fail:** With `bin span=10m`, the burst was split into a 09:10 bucket and a 09:20 bucket. A sliding window fixes that.

**Title: `DET - Low-Volume Domain Recon by Non-Privileged User (T1087.002/T1069.002/T1482)`**
```spl
index=windows EventCode=4688
| eval proc=lower(mvindex(split(NewProcessName,"\\"),-1))
| where proc IN ("net.exe","nltest.exe","whoami.exe","ipconfig.exe","arp.exe","nbtstat.exe")
| where NOT match(SubjectUserName,"\$$") AND MandatoryLabel!="S-1-16-12288" AND MandatoryLabel!="S-1-16-16384"
| eval cmd=lower(CommandLine)
| eval domain_hit=if(match(cmd,"/domain|domain_trusts|trusted_domains|dclist|dsgetdc|domain admins|enterprise admins"),1,0)
| sort 0 host SubjectUserName _time
| streamstats time_window=15m dc(proc) as distinct_tools sum(domain_hit) as domain_cmds values(proc) as tools values(CommandLine) as cmds by host SubjectUserName
| where distinct_tools>=3 AND domain_cmds>=1
| stats min(_time) as first_seen max(_time) as last_seen max(distinct_tools) as distinct_tools max(domain_cmds) as domain_cmds values(tools) as tools values(cmds) as cmds by host SubjectUserName
| convert ctime(first_seen) ctime(last_seen)
```
- **Keys on:** `NewProcessName`, `CommandLine`, `SubjectUserName`, `host` and `MandatoryLabel`.
  - `net1.exe` is dropped because every `net.exe` call spawns it, so it would double-count.
  - Machine accounts (`$`) and High/System integrity processes are excluded, which is how the rule targets non-privileged users.
- **Threshold:** At least 3 distinct tools within 15 minutes, plus at least 1 domain-scope command.
  - bob scored 6 distinct tools and 5 domain-scope commands.
  - Requiring a domain-scope command is what separates attacker recon from a user troubleshooting with `ipconfig` and `arp`.
  - The 15-minute window catches activity paced at roughly 1–2 minutes apart. Your existing ≥100/min rule is blind to that.
  - Schedule every 10 minutes over the last 30 minutes, and throttle on `host,SubjectUserName` for 1 hour.
- **False positives and tuning:**
  - Expect helpdesk staff and IT scripts run as standard users, login scripts calling `net use` or `net time`, and VPN or network troubleshooting.
  - Tune with an allowlist lookup of IT/helpdesk accounts and known parent scripts (filter on `ParentProcessName`). Don't raise the tool count, because that is what lets low-and-slow activity through.
  - If you want more recall for slower operators, add a second tier with a 60-minute window and ≥4 tools.
- **MITRE:** T1087.002 (Domain Account), T1069.002 (Domain Groups), T1482 (Domain Trust Discovery), plus T1016 and T1033 as supporting techniques.

## 3. Sysmon ProcessCreate tuning

**What the data shows:** Sysmon logged `nltest /domain_trusts` but not `/trusted_domains`, and logged no `arp.exe` at all. The `technique_id=` RuleNames show this is sysmon-modular style. The nltest include is matching on CommandLine substrings, and arp has no include at all.

**Change:** Add an include block keyed on `OriginalFileName`. That field survives renaming, which `Image` does not. The values below are what your own events report (nltest is `nltestrk.exe`, nbtstat is `nbtinfo.exe`). Keep the `Image` fallback for the arp entry until you've seen one arp event and can confirm its OriginalFileName.
```xml
<RuleGroup name="" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Rule name="technique_id=T1482,technique_name=Domain Trust Discovery" groupRelation="or">
      <OriginalFileName condition="is">nltestrk.exe</OriginalFileName>
    </Rule>
    <Rule name="technique_id=T1016,technique_name=System Network Configuration Discovery" groupRelation="or">
      <OriginalFileName condition="is any">arp.exe;nbtinfo.exe;ipconfig.exe;route.exe;netsh.exe</OriginalFileName>
      <Image condition="end with">\arp.exe</Image>
    </Rule>
  </ProcessCreate>
</RuleGroup>
```
Then delete or neutralise the old nltest CommandLine-substring rule, so logging every nltest call becomes the authoritative rule. Push the config with `sysmon -c config.xml` and verify with `arp -a` and `nltest /trusted_domains`.

**Trade-off:**
- These binaries are rare on endpoints, so the extra volume is small. Workstations will add a few events a day.
- The heavy part is noisier boxes: jump hosts, admin workstations and monitoring servers that poll `arp` or `netsh` on a schedule. If one of those floods, add a targeted exclude (parent plus host) rather than removing the include.
- The structural lesson: include-on-command-line rules are brittle. Attackers vary their arguments, and every argument you didn't anticipate is silently dropped. Include on the binary, then filter in Splunk. And because Sysmon depends on its config, keep 4688 command-line auditing on as the backstop.

## Priority

1. **Run key persistence (#1) is the top priority.** It's the biggest gap: you have zero coverage today. Persistence also means the attacker survives reboots and comes back, while recon alone doesn't. And it's the cheapest rule to run: it's a single event, has high fidelity, and the data already arrives with only two known legitimate writers.
2. **Recon (#2) is second.** It catches the attacker earlier in the kill chain, but it needs FP tuning with real helpdesk behaviour before it can be a paging alert.
3. **Sysmon tuning (#3) is third.** It's a visibility fix rather than a detection. 4688 already covers the gap for rule #2, so it's important but not urgent.