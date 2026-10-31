"""
ingest.py - build a local knowledge index for the SOC RAG analyst.

Reads .md / .spl / .txt / .conf files from CORPUS_DIRS, splits them into
overlapping chunks, embeds each chunk with a local Ollama embedding model,
and saves everything to index.pkl. No cloud, no database - just a pickle.

Run:  python ingest.py
"""
import os, glob, pickle, sys
import requests

OLLAMA = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"
INDEX_FILE = "index.pkl"

# Folders to read knowledge from. Point these at your cloned repos.
# Edit these paths to match your machine.
CORPUS_DIRS = [
    r"C:\soc-rag\corpus",            # drop any extra notes/runbooks here
    # r"C:\Users\User\ai-soc-triage-lab",     # <- your cloned repo (uncomment + fix path)
    # r"C:\Users\User\soc-purple-team-homelab",
]
EXTENSIONS = (".md", ".spl", ".txt", ".conf")
CHUNK = 900          # characters per chunk
OVERLAP = 150        # characters shared between neighbouring chunks


def embed(text):
    r = requests.post(f"{OLLAMA}/api/embeddings",
                      json={"model": EMBED_MODEL, "prompt": text}, timeout=120)
    r.raise_for_status()
    return r.json()["embedding"]


def chunk_text(text):
    text = text.strip()
    out, i = [], 0
    while i < len(text):
        out.append(text[i:i + CHUNK])
        i += CHUNK - OVERLAP
    return [c for c in out if c.strip()]


def check_ollama():
    try:
        tags = requests.get(f"{OLLAMA}/api/tags", timeout=10).json()
    except Exception as e:
        sys.exit(f"[!] Cannot reach Ollama at {OLLAMA}. Is the Ollama app running?  ({e})")
    names = [m["name"] for m in tags.get("models", [])]
    if not any(n.startswith(EMBED_MODEL) for n in names):
        sys.exit(f"[!] Embedding model '{EMBED_MODEL}' not found. Run:  ollama pull {EMBED_MODEL}")


def main():
    check_ollama()
    files = []
    for d in CORPUS_DIRS:
        if os.path.isdir(d):
            for ext in EXTENSIONS:
                files += glob.glob(os.path.join(d, "**", "*" + ext), recursive=True)
    files = sorted(set(files))
    if not files:
        sys.exit("[!] No files found. Edit CORPUS_DIRS at the top of ingest.py to point at your docs.")

    index = []
    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception as e:
            print(f"  skip {path}: {e}"); continue
        chunks = chunk_text(text)
        for n, ch in enumerate(chunks):
            index.append({"text": ch, "source": os.path.basename(path), "path": path,
                          "chunk": n, "embedding": embed(ch)})
        print(f"  indexed {os.path.basename(path):45s} {len(chunks):3d} chunks")

    with open(INDEX_FILE, "wb") as f:
        pickle.dump(index, f)
    print(f"\n[+] Done. {len(index)} chunks from {len(files)} files -> {INDEX_FILE}")


if __name__ == "__main__":
    main()
