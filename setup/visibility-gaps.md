# Visibility Gaps — telemetry coverage findings

A running list of detection-coverage gaps found by querying the lab's own Splunk,
where a detection **cannot fire because the required telemetry is not being collected**.
Each entry is a live verification, not a guess — an empty hunt is only "all clear"
once the data it depends on is confirmed present.

---

## VG-001 — Kerberos Service Ticket Operations (4769) not audited on the DC

- **Verified:** 2026-11-14, live via Splunk MCP (least-privilege `mcp_ai` identity)
- **Affects:** DET-025 (Kerberoasting, T1558.003) — all three rules depend on 4769
- **Severity:** detection blind spot (a Kerberoast would currently be invisible)

### What was checked

Coverage of 4769 across every index over 90 days:

```
index=* EventCode=4769   (earliest=-90d)
| stats count by index
  -> win_dc: 1 event in 90 days
```

Event-code profile of the DC over 7 days — 4768 (Kerberos TGT) flows normally,
4769 (Kerberos service ticket) is effectively absent:

```
index=win_dc   (earliest=-7d)
| stats count by EventCode sourcetype
| sort - count
  -> 4688, 4624, 4634, 5145, 5140 ... 4768 = 87 ... (no 4769)
```

### Impact

DET-025 matches `EventCode=4769 Status=0x0 TicketEncryptionType=0x17`. With ~0
4769 events reaching Splunk, the rule cannot fire — an attacker Kerberoasting
`svc_sql` (or any service account) would leave no detectable trace. The empty
hunt result is therefore a **visibility gap, not a clean result**.

DET-025 already lists 4769 as a prerequisite; this entry records that, as of
2026-11-14, that prerequisite is **still unmet**.

### Fix

On the DC, via GPO:

```
Computer Configuration -> Policies -> Windows Settings -> Security Settings
 -> Advanced Audit Policy Configuration -> Audit Policies -> Account Logon
 -> "Audit Kerberos Service Ticket Operations" = Success (and Failure)
```

Then `gpupdate /force`. Let benign 4769s (including machine-account `$`) flow
and accumulate before trusting DET-025 thresholds.

### Re-verify after enabling

```
index=win_dc EventCode=4769 earliest=-24h
| stats count by TicketEncryptionType
```

Report Title: `AUDIT - 4769 coverage after GPO enable`

---

*Method note:* a first hunt used the field name `Ticket_Encryption_Type`; the
correct extracted field in this pipeline is `TicketEncryptionType`. The coverage
check above does not depend on that field, so the gap finding stands regardless.
