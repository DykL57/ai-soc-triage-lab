# AI-Assisted SOC Triage — Local vs. Cloud LLMs on Real Splunk Data

**Can an AI reach the same verdict as an analyst, from the same evidence?** This repository documents one day of experiments in my [SOC / purple team home lab](https://github.com/DykL57/soc-purple-team-homelab), answering that question with real Windows, Sysmon and firewall data in Splunk.

Every AI result was checked against a human investigation of the same alert. Where the AI was right and the human was wrong, the ground truth was corrected.

---

## The setup

```
Lab hosts (DC01, workstations, file server, scanner, red team)
        │  Universal Forwarder / syslog
        ▼
SPLUNK01 — Splunk Enterprise ──── Splunk MCP Server (19 tools)
        ▲                                   │
        │ SPL searches                      │ least-privilege AI identity
        │                                   ▼
   Analyst (human) ◄── same evidence ──► AI client
                                         ├─ Claude (cloud)
                                         └─ Qwen 3.5 9B (local, Ollama, RTX 5050 8GB)
```

- The AI connects through the official **Splunk MCP Server** app with a dedicated read-only role: five lab indexes, 30-day search window, 2 concurrent searches, no real-time searches.
- Every SPL query the AI wanted to run was reviewed by a human before it ran.
- Setup details and every error hit along the way: [`setup/splunk-mcp-setup.md`](setup/splunk-mcp-setup.md).

---

## The test

One alert: **more than 10 failed Windows logons (EventCode 4625) for the same account within 5 minutes**, on the domain controller, last 30 days.

Ground truth from the manual investigation ([Eval 01](evals/01-local-llm-spl-no-tools.md)): 30 account bursts from three sources, all benign:

| Source | What it looked like | What it was |
|---|---|---|
| 10.0.20.120 | Password spray against 28 accounts in 46 seconds | Authorized vulnerability scanner (Greenbone) |
| 10.0.30.101 | 29 failures, then a domain admin success, `PowerShell -ExecutionPolicy Bypass`, silent `msiexec` | Manual Zabbix agent install |
| 10.0.50.105 | Repeated wrong password for `Administrator` | Zabbix install script run as the local Administrator against the DC share |

The second source is the hard one: without context it is indistinguishable from attacker tradecraft.

---

## Results

| Run | Model | Tools | Context | Corrections | Detection | Verdicts |
|---|---|---|---|---|---|---|
| [01](evals/01-local-llm-spl-no-tools.md) | Qwen 3.5 9B (local) | none | none | — | ❌ invalid SPL in 3 runs | — |
| [02](evals/02-cloud-llm-mcp-no-context.md) | Claude (cloud) | Splunk MCP | none | 0 | ✅ better than the human reference | 1 of 3 (+1 partial) |
| [02b](evals/02b-cloud-llm-mcp-asset-context.md) | Claude (cloud) | Splunk MCP | asset lookup | 0 | ✅ | **3 of 3** |
| [02c](evals/02c-local-llm-mcp-unguided.md) | Qwen 3.5 9B (local) | Splunk MCP + local tools | asset lookup | 0 | ❌ | 0 |
| [02d](evals/02d-local-llm-mcp-guided.md) | Qwen 3.5 9B (local) | Splunk MCP only | asset lookup + hints | 3 | ❌ | 0 |

[**Eval 04**](evals/04-ai-red-vs-blue.md) and [**Eval 05**](evals/05-label-reliance.md) are a different experiment: a real Atomic Red Team attack chain, a blind AI investigation of it, an LLM asked (and refusing) to play the attacker, an LLM building the detections for the gaps, and a test of whether the AI judges by behaviour or by a reassuring label. See below.

---

## Key findings

1. **Tool access changes everything — for a model that can use it.** Without tools, the local model guessed field names and claimed SPL has no sliding window. With Splunk access, the cloud model checked the schema first, found a duplicated field extraction on its own, and wrote a better detection than the human reference (case-insensitive accounts, burst grouping).

2. **Detection quality and verdict quality are different skills.** With a perfect detection and no asset context, the cloud model called the authorized scanner "a dictionary attack, likely Hydra or CrackMapExec". One lookup table fixed it — and the model then went looking for independent evidence (a port scan in the firewall logs) instead of trusting the inventory alone.

3. **The AI corrected the human.** On FILE-SRV01 the manual investigation stopped at "probably a mapped drive". The AI found the actual cause (a Zabbix install script run as the local Administrator) and it was verified to the second. In return, the human caught an AI timeline built from an aggregated query (`min(_time)` + `values()` per executable) that could not prove what it claimed.

4. **A silent tool default produced a false negative.** The local model never set the search time range. The tool defaulted to 6 hours, every search came back empty, and the model concluded "there are no failed logons" — for a 30-day investigation with more than 1,500 of them.

5. **An agent with a shell is a security boundary.** The local model treated a Splunk lookup as a local file and ran `find /` across the whole host disk. Read-only and harmless, but approved by habit. Investigation agents in this lab now run with local tools disabled.

6. **A 9B local model is a junior analyst who needs a senior next to every query.** Shown the data (`table *`), it fixed its field names immediately and found the right three sources. It never recovered from its own SPL errors, invented syntax when unsure, and reached no verdicts after three corrections.

---

## Eval 04 — AI on both sides of a real attack

[Full write-up.](evals/04-ai-red-vs-blue.md) A four-stage Atomic Red Team chain was run as a standard user (discovery → trust mapping → Run-key persistence), then investigated three ways:

- **AI investigates blind.** Given one alert and no mention of Atomic Red Team, the cloud model reconstructed all four stages in the right order, found the pre-attack setup and a Defender evasion on its own, and reached the right posture — *benign, but confirm authorization with the customer*, not auto-close.
- **AI asked to be the attacker — and refused.** Asked to generate an evasion-optimised attack playbook (even framed as an authorized lab), the model declined and offered the defender's seat instead. Nothing ran. For an AI-powered-attack defender, that refusal is itself the result.
- **AI as detection engineer.** The same prompt run twice: once it guessed field names and wrote a detection that returned nothing; once it inspected the data first and wrote two validated rules. Same model — the process decided the outcome. The rules ([DET-023](detections/DET-023-run-key-persistence.spl), [DET-024](detections/DET-024-low-volume-ad-recon.spl)) close real gaps: no Run-key persistence coverage, and an AD-recon rule blind to low-and-slow native discovery.
- **[Label or behaviour?](evals/05-label-reliance.md)** The same attack re-run with a legitimate-looking value name (`SystemHealthMonitor`) and no "test" markers. The AI flagged the name as *masquerading* (a red flag, not reassurance) and judged the event by behaviour — but reached "benign" by correlating to the morning's test activity still in the SIEM. The lesson: when you evaluate an AI analyst, what's in the search window is part of the experiment.
- **[A fully local SOC analyst](local-rag-analyst/).** A retrieval-augmented analyst — Qwen 3.5 9B + a local embedding index of this repo, on 8 GB of VRAM, nothing leaving the host. It answers from the lab's own detections and evals with citations, and when asked about a technique the repo doesn't cover (Kerberoasting), it says so instead of inventing one. The privacy half of the local-vs-cloud trade-off, made real.

---

## What this means for an AI-assisted SOC

- **Give the AI context, not just data.** Asset inventory, authorized activity and change records turned a wrong verdict into a right one.
- **Ask for the query behind every claim, and read it.** A cited query is only evidence if it can actually prove the claim.
- **Treat the AI as an identity.** Least-privilege role, scoped indexes, search limits, per-call approval for SPL, no shell.
- **Local vs. cloud is a real trade-off.** Local kept every log on the host but could not do the job on 8GB of VRAM; the cloud model did the job but the data left the environment. For customer data, that decision belongs to policy and contracts, not convenience.

---

## Contents

```
ai-soc-triage-lab/
├── README.md
├── evals/          seven evaluations with methods, results and lessons
├── detections/     validated detections: brute force, Run-key persistence, low-volume AD recon, Sysmon tuning
├── lookups/        lab_assets.csv — the asset inventory used for enrichment
├── setup/          Splunk MCP setup, least-privilege role, troubleshooting log
├── local-rag-analyst/  a fully local RAG SOC analyst (Qwen + embeddings) over this repo
└── evidence/       session transcripts (blue investigation, detection engineering, red refusal) and screenshots
```

## Next

- Label-reliance test: re-run the persistence with a neutral value name and check whether the blue AI judges by behaviour or by the "Atomic Red Team" label.
- Deploy DET-023/DET-024 as scheduled searches, build an IT/helpdesk allowlist, re-run the chain, and measure precision.
- Same evidence, verdict-only test on the hardest brute-force case (the Zabbix install that looks like an attack).
- Larger local models (MoE in system RAM, or a 24GB+ GPU) on the same prompts.
