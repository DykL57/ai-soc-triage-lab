# Eval 06 — Kerberoasting: closing a gap the AI found

**The loop that led here:** the [local RAG analyst](../local-rag-analyst/) was asked "what is our
detection coverage for Kerberoasting?" and correctly answered that there was none. So I ran the
attack, investigated the telemetry, and had the AI build the detection. This eval closes that gap.

- **Date:** 2026-10-31
- **Technique:** T1558.003 — Kerberoasting (an **identity** attack; `identity` is a core Artemis requirement)
- **Why it matters:** any domain user can request a service ticket for an SPN account and crack it
  offline — no elevation, no server logon. It is one of the most common AD attacks and needs a
  dedicated detection.

## Setup

On DC01: created a service account `svc_sql` with an SPN (`MSSQL/db01.lab.local:1433`), forced it to
RC4 (`msDS-SupportedEncryptionTypes=4`, a realistic legacy misconfiguration), and **enabled Kerberos
Service Ticket auditing (4769)** — which the AI had flagged as missing back in Eval 4a.

## Attack (as `LAB\bob.user`, a standard user, no downloads)

| Time | Command | Step |
|---|---|---|
| 11:17:40 | `setspn -T lab.local -Q */*` | SPN enumeration (find roastable accounts) |
| 11:17:49 | `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken "MSSQL/db01.lab.local:1433"` | request the service ticket |

`klist` showed the svc_sql ticket as **RC4-HMAC** while every other ticket in the session was
AES-256 — the RC4 ticket is the anomaly. We stop at the request: exporting and cracking the hash
(Rubeus/hashcat) is where the harm is, and the detectable signal (4769) already exists without it.

**Ground truth (verified via MCP):** `win_dc` 4769 at 11:17:49, `ServiceName=svc_sql`,
`TargetUserName=bob.user@LAB.LOCAL`, `TicketEncryptionType=0x17` (RC4), from 10.0.30.100, Status 0x0.

## AI-built detection (DET-025)

Claude inspected the 4769 data first and found:

- **Thin baseline.** Only one 4769 in all history — the test — because auditing was just enabled
  (714 4768 events over 30 days, all AES256). It said plainly: let benign 4769s accumulate before
  trusting thresholds.
- **A real pipeline bug, re-found.** `IpAddress` is extracted twice in `win_dc` (multivalue), so a
  plain `replace()` returns null and `stats ... by src_ip` silently drops the event — its first draft
  missed the test for exactly this reason, then fixed it with `mvindex(IpAddress,0)`. Same
  duplicate-extraction issue seen in the brute-force detection; worth fixing at `props.conf`.

It delivered two complementary rules plus a correlation signal — [DET-025](../detections/DET-025-kerberoasting.spl):

- **Rule 1 — RC4 service ticket for a user SPN.** High fidelity in an all-AES domain: a single RC4
  user-SPN ticket is already abnormal. Fires on the test (verified via MCP). Blind to attackers who
  request AES.
- **Rule 2 — one account requesting many distinct user SPNs (any encryption).** Catches mass/AES
  roasting Rule 1 can't see; correctly does **not** fire on a single-target roast; needs 4769 history
  to tune. Honest about the trade-off.
- **Rule 3 (correlation) — SPN enumeration** (`setspn -Q`, `GetUserSPNs`, `KerberosRequestorSecurityToken`),
  which ran 9 seconds before the ticket request.

It named the blind spots itself: AES roasting, throttled requests, and small domains with few SPNs
(this lab is currently one).

## Takeaways

- **The tooling chain closed its own loop:** the local AI analyst identified the coverage gap, and
  the cloud AI built the detection for it — both verified by a human against ground truth.
- **Detection is a system, not a rule:** the detection was only possible after enabling the right
  audit policy, and only correct after fixing a field-extraction bug. The AI surfaced both.
- **One encryption type isn't enough:** RC4 is the high-fidelity signal today, but a behavioural rule
  is needed for the AES case — defence in depth, stated as such.

## Next

- Let 4769 accumulate for 1–2 weeks, then set Rule 2's threshold from the real per-user distribution.
- Fix the duplicate `IpAddress` extraction in `win_dc` at `props.conf`.
- Remediate `svc_sql` properly (AES + a strong password) and confirm Rule 1 goes quiet.
