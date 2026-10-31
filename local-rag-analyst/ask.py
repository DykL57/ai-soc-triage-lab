"""
ask.py - ask your local SOC analyst a question, answered ONLY from your own
knowledge index, with sources.

Run:  python ask.py "how do I detect run key persistence?"
  or: python ask.py          (interactive - keeps asking)
"""
import sys, pickle, math
import requests

OLLAMA = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"
CHAT_MODEL = "qwen3.5:9b"      # <- your local model
INDEX_FILE = "index.pkl"
TOP_K = 5

SYSTEM = (
    "You are a SOC analyst assistant. Answer ONLY from the CONTEXT below, which comes "
    "from the user's own lab notes, detections and ATT&CK references. If the answer is "
    "not in the context, say so plainly - do not invent. Cite the source file in brackets "
    "after each claim, e.g. [DET-023-run-key-persistence.spl]. Be concise and technical."
)


def embed(text):
    r = requests.post(f"{OLLAMA}/api/embeddings",
                      json={"model": EMBED_MODEL, "prompt": text}, timeout=120)
    r.raise_for_status()
    return r.json()["embedding"]


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb + 1e-9)


def retrieve(index, question):
    q = embed(question)
    scored = sorted(index, key=lambda c: cosine(q, c["embedding"]), reverse=True)
    return scored[:TOP_K]


def answer(index, question):
    hits = retrieve(index, question)
    context = "\n\n".join(f"[{h['source']}]\n{h['text']}" for h in hits)
    prompt = f"CONTEXT:\n{context}\n\nQUESTION: {question}"
    r = requests.post(f"{OLLAMA}/api/chat", json={
        "model": CHAT_MODEL, "stream": False,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": prompt}],
        "options": {"temperature": 0.1, "num_ctx": 8192},
    }, timeout=600)
    r.raise_for_status()
    said = r.json()["message"]["content"]
    srcs = sorted({h["source"] for h in hits})
    return said, srcs


def main():
    try:
        index = pickle.load(open(INDEX_FILE, "rb"))
    except FileNotFoundError:
        sys.exit("[!] No index.pkl. Run:  python ingest.py  first.")
    if len(sys.argv) > 1:
        questions = [" ".join(sys.argv[1:])]
    else:
        print("Local SOC analyst ready. Ask a question (or 'exit').")
        questions = None
    while True:
        if questions:
            q = questions.pop(0)
        else:
            q = input("\n> ").strip()
            if q.lower() in ("exit", "quit", ""):
                break
        said, srcs = answer(index, q)
        print("\n" + said)
        print("\nRetrieved from: " + ", ".join(srcs))
        if questions == []:
            break


if __name__ == "__main__":
    main()
