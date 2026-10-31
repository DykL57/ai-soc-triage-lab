# Technical summary — two days of AI-assisted SOC work

A compact, technical account of what was built and found, for reviewers who want the
substance fast. Full detail is in each eval; this is the map.

## Objective

Measure, hands-on, where LLMs help a SOC analyst and where they fail — on real Splunk
data in a purple-team lab — and build the defensive artifacts the experiments justify.
Context: interview feedback that I should know AI better. Instead of a course, I put AI
to work as an analyst and measured it.

## Environment

- **SIEM:** Splunk Enterprise. Indexes: `win_dc`, `windows` (incl. 4688 + PowerShell 4104),
  `sysmon`, `zeek`, `pfsense`.
- **AI access:** official **Splunk MCP Server**, dedicated `mcp_ai` identity — role with no
  inheritance, 5 indexes, 30-day window, 2 concurrent searches, no real-time, per-query approval.
- **Models:** Claude (cloud) via MCP; Qwen 3.5 9B (local, Ollama, RTX 5050 8 GB).
- **Attack tooling:** Atomic Red Team (ATT&CK-mapped, reversible).
- **Ground truth:** manual investigation (day 1); ART execution log + transcripts + 4104 (day 2).

## Day 1 — triage (Evals 01–02d)

One alert: >10 failed logons (4625) per account in 5 min, on the DC, 30 days. Three benign
sources (authorized scanner, two Zabbix installs); the Zabbix-via-admin case is attacker-shaped.

| Eval | Model | Tools | Context | Result |
|---|---|---|---|---|
| 01 | Qwen 9B | none | none | invalid SPL in 3 runs |
| 02 | Claude | MCP | none | detection better than the human reference; 1/3 verdicts (called the authorized scanner "Hydra/CrackMapExec") |
| 02b | Claude | MCP | asset lookup | **3/3 verdicts**; sought independent firewall evidence |
| 02c | Qwen 9B | MCP + local tools | asset lookup | 0 verdicts; ran `find /`; silent `-6h` default → false negative |
| 02d | Qwen 9B | MCP only | asset + hints | 0 verdicts after 3 corrections |

**Findings:** tool access transforms a capable model (schema-first, found a duplicated field
extraction, wrote a better burst detection); detection skill ≠ verdict skill (context fixed the
wrong verdict); the AI corrected the human root cause on FILE-SRV01 and the human caught an AI
timeline built from an aggregate that couldn't prove order; a silent tool default caused a false
negative; an agent with a shell is a security boundary; a 9B model is a junior that needs a senior
at every query.

## Day 2 — attack, blind investigation, detection engineering (Evals 04–05)

A 4-stage ART chain as a standard user (`bob.user`): T1016 → T1069.002 → T1482 → T1547.001.

- **Telemetry findings:** Defender's AMSI block of the fileless install never reached Splunk
  (`Windows Defender/Operational` not forwarded); Sysmon's include-based `ProcessCreate` silently
  dropped `arp.exe` and `nltest /trusted_domains` (4688 was the backstop); the existing AD-recon
  rule (volume-based) does not fire on low-and-slow native recon.
- **Blind AI investigation (4a):** given one alert and no mention of ART, Claude reconstructed all
  four stages in order, found the pre-attack setup and the Defender evasion, mapped ATT&CK, and
  reached the right posture — *benign, pending authorization*, not auto-close. Minor error:
  claimed no DC-side SAMR visibility when 5145 was present.
- **AI as attacker — refused (3):** asked to generate an evasion-optimized attack playbook (even as
  an authorized lab), Claude declined as dual-use and offered the defender's seat. Nothing executed.
- **AI as detection engineer (3, revised):** same prompt twice — guessed field names → 0 rows;
  inspected data first → two validated rules. Process, not model, decided the outcome.
  Delivered [DET-023](detections/DET-023-run-key-persistence.spl) (Run-key persistence, classification-based)
  and [DET-024](detections/DET-024-low-volume-ad-recon.spl) (low-volume recon, sliding window), plus a
  [Sysmon tuning note](detections/sysmon-processcreate-tuning.md).
- **Label vs behaviour (05):** re-ran the same behaviour with a legitimate-looking value name
  (`SystemHealthMonitor`) and no ART markers. The AI flagged the name as *masquerading* (not
  reassurance) and judged by behaviour, but reached benign via timeline correlation to the
  morning's test traces still in the SIEM — a confound: the search window is part of the test.
  DET-024 honestly did not fire (2 tools < the ≥3 threshold).

## Eval 06 — Kerberoasting (identity), closing a loop

The local RAG analyst (below) flagged that the lab had **no Kerberoasting coverage**, so I built it.
Ran T1558.003 as a standard user (SPN enumeration + a service-ticket request for a seeded SPN account
forced to RC4), after enabling the DC's Kerberos service-ticket auditing (4769) that Eval 4a had flagged
as missing. Ground truth: a 4769 with `TicketEncryptionType=0x17`, verified via MCP. Claude inspected the
data, noted the thin post-enablement baseline, **re-found the duplicate `IpAddress` extraction** that was
silently dropping events, and produced [DET-025](detections/DET-025-kerberoasting.spl): an RC4 user-SPN
rule (high fidelity in an all-AES domain), a behavioural mass-SPN rule (for AES/mass roasting), and an
SPN-enumeration correlation signal. The local AI found the gap; the cloud AI built the fix; a human
verified both.

## Local RAG SOC analyst

A fully local analyst: Qwen 3.5 9B + `nomic-embed-text` over a 209-chunk index of this repo,
8 GB VRAM, nothing leaving the host. Answers from the lab's own detections/evals with citations;
asked about Kerberoasting (not in the repo), it said so instead of inventing a detection. The
privacy half of the local-vs-cloud trade-off, realized. Code: [`local-rag-analyst/`](local-rag-analyst/).

## Bottom line

AI is excellent at gathering and reconstructing evidence; the verdict depends on the context it is
given, on reading the query behind every claim, and on a human owning the judgment. Treat the AI as
an identity (least privilege, approvals, no shell). Local vs. cloud is a real privacy/capability
trade-off that belongs to policy. And with AI, the process — making it inspect before it concludes,
and checking it after — decides the result more than the model does.
