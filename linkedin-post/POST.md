# LinkedIn Post — AI-SOC Triage Lab

Style: technical, learning-focused. Copy the text below into LinkedIn and attach the
four images from `images/` in the numbered order (1 → 4).

---

## Post text

Over the last two weeks I built an AI-assisted SOC triage lab — and the most useful part was watching the AI fail.

Here's what I did 👇

The setup:
• An AI agent wired into Splunk through MCP (Model Context Protocol)
• A dedicated least-privilege identity for the agent — read-only, no shell, approval required on every query
• Real attacks generated with Atomic Red Team: AD recon, Run-key persistence, and Kerberoasting

Then I asked the same question three ways: let a cloud model triage, let a local model (Qwen on Ollama) triage, and do the investigation manually myself.

What I expected: the AI finds the needle faster.
What actually happened: the AI was genuinely strong at collection and summarization — and risky wherever the process let it guess.

The honest failures (screenshots below):
• It invented a Splunk subsearch that doesn't exist, and presented it with full confidence.
• Given a shell, it ran a find across the entire disk — exactly the over-reach you never want from an automated identity.
• Without guardrails it ran away into a 32k-token loop, burning context on noise.

None of that is a reason to keep AI out of the SOC. It's the reason to engineer the process around it:
• Least privilege for the AI identity, the same as any user. Read-only. No shell. Approve sensitive actions.
• Every verdict has to rest on a query you can re-run against ground truth.
• A human holds accountability for the decision — always.

To close the loop I built a fully local RAG analyst over my own notes and detections. It answers with citations, and when the answer isn't in the source it says "I don't know" instead of inventing one. That honesty test mattered to me more than any benchmark.

Biggest takeaway: with AI, the process determines the outcome. Make it verify before it concludes, and verify it after.

Full write-up, detection rules, and the evidence — including the failures — are open on GitHub:
github.com/DykL57/ai-soc-triage-lab

#CyberSecurity #SOC #DetectionEngineering #Splunk #AI #LLM #BlueTeam #PurpleTeam #MDR

---

## Image order

1. `images/1-investigation-flow.png` — the AI agent running a structured investigation over Splunk via MCP.
2. `images/2-invented-subsearch.png` — the model confidently inventing a Splunk subsearch that does not exist.
3. `images/3-whole-disk-find.png` — the model, given a shell, running a find across the whole disk (excessive agency).
4. `images/4-token-runaway.png` — the model running away into a ~32k-token loop without guardrails.

## Notes
- No credentials, tokens, customer data, or employer data are referenced. All content is from the personal home lab.
- Keep the first comment free for the repo link if you prefer links out of the main body (LinkedIn sometimes down-ranks posts with external links in the body).
