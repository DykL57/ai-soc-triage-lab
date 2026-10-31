# Local SOC Analyst (RAG) — runs entirely on your machine

A local LLM (Qwen via Ollama) that answers SOC questions **from your own knowledge**
— your detections, your eval write-ups, ATT&CK notes — and cites its sources.
No data leaves the machine.

## How it works

```
your docs ──▶ ingest.py ──▶ chunks + embeddings ──▶ index.pkl
                                                        │
your question ──▶ embed ──▶ cosine similarity ──▶ top 5 chunks ──┐
                                                                 ▼
                                      question + chunks ──▶ Qwen ──▶ answer + [sources]
```

- **Embedding model:** `nomic-embed-text` (tiny, turns text into vectors).
- **Chat model:** `qwen3.5:9b` (your existing local model).
- **Store:** a plain `index.pkl` file + numpy-style cosine search. No database.

## Setup (Windows PowerShell, in C:\soc-rag)

```powershell
# 1. Python deps (light)
pip install requests numpy

# 2. Pull the embedding model (Ollama must be running)
ollama pull nomic-embed-text

# 3. Put knowledge in the corpus. Easiest: clone your repo next to this folder
#    and uncomment its path in CORPUS_DIRS at the top of ingest.py.
#    Or drop any .md / .spl / .txt notes into C:\soc-rag\corpus\

# 4. Build the index
python ingest.py

# 5. Ask
python ask.py "how do I detect run key persistence, and what are the false positives?"
#   or just:  python ask.py   (interactive)
```

## What to feed it

- Your `ai-soc-triage-lab` repo (the evals + detections — gold for this).
- Your `soc-purple-team-homelab` README and detection docs.
- ATT&CK technique notes (e.g. paste T1547.001, T1069.002 descriptions into corpus/).

## Why RAG and not fine-tuning

- Update instantly: add a detection, re-run `ingest.py`, it knows it. No retraining.
- Every answer shows its sources — you can verify it, which matters in a SOC.
- Runs on 8 GB VRAM: the embedding model is tiny, Qwen does the rest.

## Notes

- First answer is slow (model loads into VRAM); after that it's fast.
- If Qwen invents things, it means retrieval missed — add more/clearer source docs,
  or lower `TOP_K` noise. The system prompt tells it to say "not in my notes" instead
  of guessing.
