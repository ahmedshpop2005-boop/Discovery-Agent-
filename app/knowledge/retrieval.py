"""Local retrieval layer built on LlamaIndex document primitives.

Retrieval is deliberately local and lexical: no customer scan data is sent to
an external model or embedding provider. When LlamaIndex is not installed the
module still works using a compatible in-process fallback.
"""

from __future__ import annotations

from app.config import settings

try:  # production install
    from llama_index.core import Document
    from llama_index.core.node_parser import SentenceSplitter

    LLAMAINDEX_AVAILABLE = True
except ImportError:  # bootstrap/offline mode
    LLAMAINDEX_AVAILABLE = False

    class Document:  # type: ignore[no-redef]
        def __init__(self, text: str, metadata: dict):
            self.text = text
            self.metadata = metadata

    class SentenceSplitter:  # type: ignore[no-redef]
        def __init__(self, **_):
            pass

        def get_nodes_from_documents(self, docs):
            return docs


def _load_documents() -> list:
    base = settings.knowledge_dir
    if not base.exists():
        return []
    return [
        Document(text=path.read_text(encoding="utf-8"), metadata={"source": path.name})
        for path in sorted(base.glob("*.md"))
    ]


def _manual_chunks(text: str, max_chars: int = 700) -> list[str]:
    """Dependency-free fallback splitter that keeps paragraphs intact."""
    chunks: list[str] = []
    current = ""
    for paragraph in text.split("\n"):
        if len(current) + len(paragraph) + 1 > max_chars and current:
            chunks.append(current.strip())
            current = ""
        current += paragraph + "\n"
    if current.strip():
        chunks.append(current.strip())
    return chunks


def _nltk_ready() -> bool:
    """Whether the NLTK resources LlamaIndex's splitter needs are present.

    Checked up-front so we never trigger a (possibly proxy-blocked) download;
    when unavailable we use the dependency-free splitter instead.
    """
    try:
        import nltk

        for resource in ("tokenizers/punkt_tab", "corpora/stopwords"):
            try:
                nltk.data.find(resource)
            except LookupError:
                return False
    except Exception:
        return False
    return True


def _nodes(docs: list) -> list[tuple[str, str]]:
    """Return ``(text, source)`` pairs, preferring LlamaIndex when usable."""
    if LLAMAINDEX_AVAILABLE and _nltk_ready():
        try:
            splitter = SentenceSplitter(chunk_size=320, chunk_overlap=40)
            nodes = splitter.get_nodes_from_documents(docs)
            return [(n.text, n.metadata.get("source", "knowledge-base")) for n in nodes]
        except Exception:
            # Any remaining issue falls through to the manual splitter.
            pass
    pairs: list[tuple[str, str]] = []
    for doc in docs:
        for chunk in _manual_chunks(doc.text):
            pairs.append((chunk, doc.metadata.get("source", "knowledge-base")))
    return pairs


def retrieve(query: str, limit: int = 2) -> list[dict]:
    """Return the closest knowledge excerpts for a query string."""
    if not query:
        return []
    docs = _load_documents()
    nodes = _nodes(docs)
    terms = {t for t in query.lower().replace("_", " ").replace("-", " ").split() if len(t) > 2}

    scored: list[tuple[int, str, str]] = []
    for text, source in nodes:
        haystack = text.lower()
        score = sum(haystack.count(term) for term in terms)
        if score:
            scored.append((score, text, source))
    scored.sort(reverse=True, key=lambda row: row[0])
    return [{"excerpt": text, "source": source} for _, text, source in scored[:limit]]
