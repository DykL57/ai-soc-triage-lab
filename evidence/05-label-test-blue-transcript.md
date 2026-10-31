I'll investigate the Run key alert in Splunk, timeline activity on WIN-CL01 and the DC, then deliver a verdict, ATT&CK mapping, scope and customer summary.

Let me pull the full process timeline for bob.user on WIN-CL01 today (excluding OneDrive noise).

I worked this end to end across Sysmon, Windows Security/PowerShell logs, DC01 Security logs, pfSense and Zeek. **Verdict: benign true positive.** The alert correctly caught real persistence and discovery behaviour, but every indicator points to an adversary-emulation exercise run from bob.user's session. That classification depends on the customer confirming the exercise was authorized, and two Run keys were left behind and need cleanup.

## 1. Timeline (all times Israel, UTC+2)

**WIN-CL01 (10.0.30.100)**

| Time | Activity |
|---|---|
| 29 Oct 14:43 | bob.user runs `whoami /groups; net group 'Domain Admins' /domain; net user /domain` from PowerShell. |
| 30 Oct 08:57 / 09:44 | bob.user's session reconnects over RDP from 10.0.30.150 (4624 type 3, then type 7). |
| 09:00 | **LAB\Administrator** downloads the Atomic Red Team repo to `C:\AtomicRedTeam\` (PowerShell PID 7048). |
| 09:17–09:21 | bob.user's PowerShell (PID 2656) installs `powershell-yaml` from PowerShell Gallery and compiles with csc.exe; both are Invoke-AtomicRedTeam dependencies. It then runs atomic tests with a `whoami` before each one, which is the Invoke-AtomicTest pattern: network config discovery (ipconfig/netsh/arp/nbtstat/net config), local and domain group discovery (including Enterprise and Domain Admins), `nltest /domain_trusts`, and a Run key named **"Atomic Red Team"** pointing to `C:\Path\AtomicRedTeam.exe`. |
| 09:47 | bob.user opens a new PowerShell (PID 5748). |
| 09:57 | Notepad opens `C:\Users\bob.user\red-run-03.txt`. |
| 16:34:00 | In PID 5748: `Start-Transcript -Path $env:USERPROFILE\label-test-05.txt`. |
| 16:34:20 | `net group "domain admins" /domain`, then `Start-Sleep 20` |
| 16:34:57 | `nltest /dclist:lab.local`, then `Start-Sleep 20` |
| **16:35:32** | **Alert:** `reg add HKCU\...\Run /v SystemHealthMonitor /d C:\Windows\System32\notepad.exe`, then `Stop-Transcript`. |
| after | No new logon, no execution of the Run value, no outbound PowerShell connections, no further bob.user commands. |

**DC01 (10.0.20.10)**
- At 16:34:20, bob.user connects from 10.0.30.100 to IPC$ and the `samr` pipe. This is the DC side of `net group /domain`.
- From 09:18 to 17:03, all of bob.user's DC logons are Kerberos network logons (type 3) from WIN-CL01 only.
- On 29–30 Oct, DC01 shows no processes run by bob.user and no account, group, GPO, service or audit-policy changes (4720/4728/4732/4738/5136/7045/1102 etc.).

## 2. MITRE ATT&CK mapping

| Activity | Technique |
|---|---|
| PowerShell and cmd /c execution | T1059.001, T1059.003 |
| whoami, whoami /groups | T1033 System Owner/User Discovery |
| ipconfig /all, netsh, arp -a, nbtstat -n, net config | T1016 System Network Configuration Discovery |
| net localgroup | T1069.001 Local Groups |
| net group /domain, Domain/Enterprise Admins | T1069.002 Domain Groups |
| net user /domain (29 Oct) | T1087.002 Domain Account |
| nltest /domain_trusts | T1482 Domain Trust Discovery |
| nltest /dclist:lab.local | T1018 Remote System Discovery |
| Run keys "Atomic Red Team" and "SystemHealthMonitor" | T1547.001 Registry Run Keys |
| Atomic Red Team and powershell-yaml downloads | T1105 Ingress Tool Transfer (test tooling) |

## 3. Verdict: benign true positive, with supporting queries

The detection fired correctly on real T1547.001 behaviour. The reasons I assess it as authorized testing rather than an intrusion:

**A. The alert event and how it was created.** The value was set by reg.exe, spawned by cmd, spawned by an interactive PowerShell. The value is a masqueraded name pointing to benign notepad.exe.
```
earliest=2026-10-30T00:00:00 latest=2026-10-31T00:00:00
index=sysmon host=WIN-CL01 "SystemHealthMonitor" | table _time EventCode User Image TargetObject Details ProcessGuid ProcessId | sort _time
```

**B. The session was scripted, labelled and paced.** It started a transcript named `label-test-05.txt`, used fixed 20-second sleeps between steps, and stopped the transcript right after the Run key was set.
```
earliest=2026-10-30T16:00:00 latest=2026-10-30T17:35:00
index=windows host=WIN-CL01 source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 | eval sb=substr(ScriptBlockText,1,400) | table _time ProcessID ScriptBlockId sb | sort _time
```

**C. Atomic Red Team was staged by Administrator and executed by bob.user the same morning.** This includes the "Atomic Red Team" Run key and the `red-run-03.txt` file.
```
earliest=2026-10-30T09:00:00 latest=2026-10-30T18:00:00
index=sysmon host=WIN-CL01 (EventCode=3 OR EventCode=22 OR EventCode=11) Image="*powershell.exe" | table _time EventCode ProcessId DestinationIp DestinationPort DestinationHostname QueryName QueryResults TargetFilename | sort _time
```
```
earliest=2026-10-30T00:00:00 latest=2026-10-31T00:00:00
index=sysmon host=WIN-CL01 EventCode=1 User="LAB\\bob.user" NOT Image="*OneDrive*" | table _time Image CommandLine ParentImage ProcessId ParentProcessId | sort _time
```

**D. Process creation is corroborated by Security 4688.** This also confirms nltest.exe, which Sysmon did not log.
```
earliest=2026-10-30T16:30:00 latest=2026-10-30T16:40:00
index=windows host=WIN-CL01 EventCode=4688 NewProcessName IN ("*\\nltest.exe","*\\reg.exe","*\\net.exe","*\\net1.exe") | table _time SubjectUserName NewProcessName CommandLine ParentProcessName | sort _time
```

**E. On the DC, the activity was enumeration only.** There is a SAMR query at the alert time and no changes or remote execution.
```
earliest=2026-10-30T16:30:00 latest=2026-10-30T16:40:00
index=win_dc host=DC01 EventCode IN (5140,5145) SubjectUserName="bob.user" | stats count values(ShareName) as share values(RelativeTargetName) as target values(IpAddress) as src by _time | sort _time
```
```
earliest=2026-10-30T08:00:00 latest=2026-10-30T18:00:00
index=win_dc host=DC01 EventCode IN (4720,4722,4724,4725,4726,4728,4732,4738,4740,4756,4672,4698,4699,4697,7045,5136,4662,4661,4799,4798,4769,1102,4719) | stats count min(_time) as first max(_time) as last values(SubjectUserName) as subject values(TargetUserName) as target by EventCode
```
(0 results)
```
earliest=2026-10-29T00:00:00 latest=2026-10-31T00:00:00
(index=win_dc host=DC01 EventCode=4688 (SubjectUserName="bob.user" OR TargetUserName="bob.user")) OR (index=sysmon host=DC01 EventCode=1 User="*bob.user*") | table _time index EventCode NewProcessName Image CommandLine
```
(0 results)

**F. Neither persistence value has been removed, and neither has executed.**
```
earliest=2026-10-29T00:00:00 latest=2026-10-30T17:40:00
index=sysmon host=WIN-CL01 EventCode IN (12,13,14) TargetObject="*\\CurrentVersion\\Run*" | table _time EventCode EventType User Image TargetObject Details | sort _time
```

**G. Network:** egress from WIN-CL01 between 16:00 and 17:35 goes only to internal infrastructure (DC, Splunk, Zabbix) and Microsoft/CDN addresses. Sysmon recorded no PowerShell network connections after 09:18.
```
earliest=2026-10-30T16:00:00 latest=2026-10-30T17:35:00
index=pfsense ("10.0.30.100" OR "10.0.30.150") | rex "(?<proto>tcp|udp|icmp),\d+,(?<src>\d+\.\d+\.\d+\.\d+),(?<dst>\d+\.\d+\.\d+\.\d+),(?<sport>\d+),(?<dport>\d+)" | rex "^(?:[^,]*,){6}(?<action>pass|block)" | stats count by src dst dport action | sort -count | head 30
```

**What would flip this to a true positive:** the customer has no record of a test on WIN-CL01, or bob.user did not run it. In particular, the RDP source 10.0.30.150 has not been identified.

## 4. Scope

- **Hosts:** WIN-CL01, with persistence and discovery. DC01 was the target of read-only enumeration (SAMR/LDAP) and was not compromised. WIN-CL02 shows no related activity.
  ```
  earliest=2026-10-29T00:00:00 latest=2026-10-30T17:40:00
  index=sysmon (EventCode=1 (Image IN ("*\\net.exe","*\\net1.exe","*\\nltest.exe","*\\reg.exe","*\\whoami.exe") OR User="*bob.user*")) OR (EventCode=13 TargetObject="*\\CurrentVersion\\Run\\*" NOT Image="*msedge.exe" NOT Image="*OneDrive*") | stats count values(User) as users values(Image) as images by host
  ```
- **Accounts:** LAB\bob.user executed everything. LAB\Administrator staged the Atomic Red Team tooling on WIN-CL01.
- **Other source:** 10.0.30.150 is the RDP client for bob.user's session. It is not in Splunk and needs to be identified.
- **Visibility gaps:**
  - DC01 does not audit 4661/4662/4769, so LDAP and Kerberos service-ticket detail is missing.
  - Zeek only covers 10.0.50.0/24, not the 10.0.30.0/24 client subnet.
  - The Sysmon config missed nltest.exe.

## 5. Customer summary

> On 30 Oct 2026 at 16:35 we detected a new startup registry entry ("SystemHealthMonitor") created under user bob.user on WIN-CL01. Our investigation found it was created as part of a scripted session that also listed Domain Admins and domain controllers. It followed an Atomic Red Team test run earlier that day from the same account, after the toolkit was installed by the Administrator account. The entry launches only Notepad. We found no malicious payload, no suspicious outbound connections, no changes on the domain controller and no spread to other hosts. We have classified this as a **benign true positive (security testing)**, pending your confirmation that this testing was authorized.
>
> **Action needed:** (1) Confirm the test was authorized and that bob.user and the RDP source 10.0.30.150 were part of it. (2) Remove the leftover startup entries "SystemHealthMonitor" and "Atomic Red Team" from bob.user's Run key, and remove `C:\AtomicRedTeam` when testing ends. (3) Consider enabling directory-service and Kerberos service-ticket auditing on DC01 to improve future visibility.

I can turn this into a shareable case report doc if you want to send it to the customer.