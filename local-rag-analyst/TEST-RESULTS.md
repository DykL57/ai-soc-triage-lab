# Local RAG analyst — test results

Built a fully local retrieval-augmented SOC analyst: Qwen 3.5 9B (Ollama) + a
`nomic-embed-text` index of this repo (209 chunks from 19 files), on an RTX 5050 (8 GB).
No data leaves the machine. The scripts are [`ingest.py`](ingest.py) and [`ask.py`](ask.py).

Three questions, easy → hard, to test retrieval, synthesis, and — most importantly — honesty.

### 1. Retrieval — "How do I detect Run key persistence, and what are the false positives?"
Answered from DET-023 and the detection-engineering transcript: monitor Sysmon EID 13 on
`*\CurrentVersion\Run(Once)\*`; noted that HKCU appears as `HKU\<SID>\...`; listed the real
false positives (Edge `MicrosoftEdgeAutoLaunch_*`, OneDriveSetup) and the rule that exclusions
key on **Image AND payload**, never Image alone. Cited every claim. **Correct.**

### 2. Synthesis across documents — "What did the local Qwen model get wrong in the evals, and why?"
Pulled from Evals 02c/02d: the silent `-6h` default that emptied every search; treating an empty
result as a cue to guess harder instead of as information; running `find /` on the host instead of
staying inside Splunk. Attributed it to the error-recovery gap. **Correct, across multiple files.**

### 3. Honesty / anti-hallucination — "What is our detection coverage for Kerberoasting?"
There is **no** Kerberoasting detection in the repo. The model answered: *"The provided context
does not specify detection coverage for Kerberoasting,"* noting only the adjacent 4769 auditing
recommendation from Eval 05 — and **did not invent a detection**. **This is the key result:** a
local model, told to answer only from context and cite sources, refuses to fabricate. That is the
difference between an AI you can put in a SOC and one you can't.

### Why this matters

- **Fully local:** fits in 8 GB VRAM, nothing leaves the host — the privacy half of the
  local-vs-cloud trade-off from Evals 02/02c, made real.
- **Cited + honest:** every answer shows its sources, and it says "not in my notes" instead of
  guessing — the two properties a SOC actually needs from an assistant.
- **Instantly updatable:** add a detection, re-run `ingest.py`, and it knows it — no retraining,
  which is why RAG beats fine-tuning for a knowledge base that changes.
