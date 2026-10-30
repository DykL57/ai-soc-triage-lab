# Sysmon ProcessCreate tuning — a coverage gap found during Eval 04

## The problem (observed, not theoretical)

WIN-CL01's Sysmon `ProcessCreate` section is `onmatch="include"` (an allow-list):
only explicitly listed processes are logged. During the manual attack chain on
2026-10-30, two commands produced **no Sysmon process event at all**:

| Command | Sysmon EID 1 | Security 4688 |
|---|---|---|
| `arp -a` | missing (no include rule for `arp.exe`) | present |
| `nltest /trusted_domains` | missing | present |
| `nltest /domain_trusts` | present (CommandLine include matched `/domain_trusts`) | present |

The include rules are compound rules tagged with ATT&CK technique IDs
(sysmon-modular style). The `nltest` rule matches on the **command-line substring**
`/domain_trusts`, so the same binary with a different argument (`/trusted_domains`)
was dropped. `arp.exe` has no include rule, so it was never logged.

**Structural lesson:** include-on-command-line rules are brittle. An attacker varies
arguments, and every argument you did not anticipate is silently dropped.

## The change

Add an include block keyed on `OriginalFileName`, which survives binary renaming
(`Image` does not). Values below are what the lab's own events report.

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

Then remove/neutralise the old `nltest` CommandLine-substring rule so that logging
*every* nltest call becomes the authoritative behaviour. Push and verify:

```
sysmon -c config.xml
arp -a
nltest /trusted_domains
```

Both should now appear in Sysmon EID 1.

## Trade-off

- These binaries are rare on endpoints, so the added volume is small (a few events/day
  per workstation).
- The noisy cases are jump hosts, admin workstations and monitoring servers that poll
  `arp`/`netsh` on a schedule. If one floods, add a targeted **exclude** (parent + host),
  don't remove the include.
- Because Sysmon depends entirely on its config, **keep Windows Security 4688 command-line
  auditing on as the backstop** — it is what covered this gap during the exercise, and it
  is the source DET-024 is built on.

> Verified by Claude over Splunk MCP (Eval 04); `OriginalFileName` values taken from the
> lab's own `index=sysmon` events. Confirm the `arp.exe` OriginalFileName against a real
> event after the first arp execution post-change.
