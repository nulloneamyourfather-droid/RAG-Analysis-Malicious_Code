import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer

try:
    import faiss  # type: ignore
except ImportError:
    faiss = None

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
except ImportError:
    SentenceTransformer = None


PROJECT_ROOT = Path(__file__).resolve().parent
RAG_ATTACK_PATH = PROJECT_ROOT / "data" / "rag" / "attack" / "attack_knowledge_for_rag.jsonl"
RAG_API_CHAIN_PATH = PROJECT_ROOT / "data" / "rag" / "api_chain" / "api_chain_knowledge_for_rag.jsonl"
RAG_IDA_PATH = PROJECT_ROOT / "data" / "rag" / "ida_semantic" / "ida_semantic_knowledge_for_rag.jsonl"
INDEX_DIR = PROJECT_ROOT / "data" / "index" / "faiss"

DOC_STORE_PATH = INDEX_DIR / "rag_docs.json"
METADATA_PATH = INDEX_DIR / "rag_index_metadata.json"

TFIDF_VECTORIZER_PATH = INDEX_DIR / "tfidf_vectorizer.joblib"
TFIDF_MATRIX_PATH = INDEX_DIR / "tfidf_matrix.npz"

SEMANTIC_EMBEDDINGS_PATH = INDEX_DIR / "semantic_embeddings.npy"
SEMANTIC_FAISS_PATH = INDEX_DIR / "semantic_faiss.index"

DEFAULT_SEMANTIC_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_MODEL_CACHE: Dict[Tuple[str, bool], Any] = {}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def unique_strs(items: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        item = str(item or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def normalize_tokens(text: str) -> List[str]:
    token = []
    out: List[str] = []
    for ch in text.lower():
        if ch.isalnum() or ch in {"_", "@", "?", "."}:
            token.append(ch)
        else:
            if token:
                out.append("".join(token))
                token = []
    if token:
        out.append("".join(token))
    return out


def build_doc_text(doc: Dict[str, Any]) -> str:
    fields = [
        doc.get("title", ""),
        doc.get("summary", ""),
        doc.get("content", ""),
        " ".join(doc.get("tags", [])),
        " ".join(doc.get("keywords", [])),
        " ".join(doc.get("attack_ids", [])),
    ]
    return "\n".join(str(field) for field in fields if field)


def load_all_rag_docs() -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []
    for path in [RAG_ATTACK_PATH, RAG_API_CHAIN_PATH, RAG_IDA_PATH]:
        docs.extend(load_jsonl(path))
    return docs


def build_index_payload() -> Tuple[List[Dict[str, Any]], List[str]]:
    docs = load_all_rag_docs()
    texts = [build_doc_text(doc) for doc in docs]
    return docs, texts


def load_sentence_model(model_name: str, allow_download: bool = False) -> Any:
    if SentenceTransformer is None:
        raise RuntimeError("sentence-transformers is not installed.")
    cache_key = (model_name, allow_download)
    model = _MODEL_CACHE.get(cache_key)
    if model is None:
        model = SentenceTransformer(model_name, local_files_only=not allow_download)
        _MODEL_CACHE[cache_key] = model
    return model


def semantic_backend_available() -> bool:
    return faiss is not None and SentenceTransformer is not None


def resolve_backend(backend: str = "auto") -> str:
    if backend == "auto":
        return "semantic" if semantic_backend_available() else "tfidf"
    if backend not in {"semantic", "tfidf"}:
        raise ValueError(f"Unsupported backend: {backend}")
    return backend


def semantic_index_exists() -> bool:
    return DOC_STORE_PATH.exists() and METADATA_PATH.exists() and SEMANTIC_EMBEDDINGS_PATH.exists() and SEMANTIC_FAISS_PATH.exists()


def tfidf_index_exists() -> bool:
    return DOC_STORE_PATH.exists() and METADATA_PATH.exists() and TFIDF_VECTORIZER_PATH.exists() and TFIDF_MATRIX_PATH.exists()


def index_exists(backend: str = "auto") -> bool:
    resolved = resolve_backend(backend)
    if resolved == "semantic":
        return semantic_index_exists()
    return tfidf_index_exists()


def build_tfidf_index(max_features: int = 20000) -> Dict[str, Any]:
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    docs, texts = build_index_payload()
    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2),
        max_features=max_features,
    )
    matrix = vectorizer.fit_transform(texts)

    save_json(DOC_STORE_PATH, docs)
    joblib.dump(vectorizer, TFIDF_VECTORIZER_PATH)
    sparse.save_npz(TFIDF_MATRIX_PATH, matrix)

    metadata = {
        "backend": "tfidf",
        "doc_count": len(docs),
        "feature_count": int(matrix.shape[1]),
        "embedding_dim": int(matrix.shape[1]),
        "sources": {
            "ATTACK": sum(1 for doc in docs if doc.get("source") == "ATTACK"),
            "API_CHAIN": sum(1 for doc in docs if doc.get("source") == "API_CHAIN"),
            "IDA_SEMANTIC": sum(1 for doc in docs if doc.get("source") == "IDA_SEMANTIC"),
        },
        "vectorizer": "TfidfVectorizer",
    }
    save_json(METADATA_PATH, metadata)
    return metadata


def build_semantic_index(model_name: str = DEFAULT_SEMANTIC_MODEL, allow_model_download: bool = False) -> Dict[str, Any]:
    if not semantic_backend_available():
        raise RuntimeError(
            "Semantic backend requires both `sentence-transformers` and `faiss`. Install them before building the semantic index."
        )

    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    docs, texts = build_index_payload()
    model = load_sentence_model(model_name, allow_download=allow_model_download)
    embeddings = model.encode(
        texts,
        batch_size=32,
        show_progress_bar=False,
        normalize_embeddings=True,
        convert_to_numpy=True,
    ).astype("float32")

    index = faiss.IndexFlatIP(int(embeddings.shape[1]))
    index.add(embeddings)

    save_json(DOC_STORE_PATH, docs)
    np.save(SEMANTIC_EMBEDDINGS_PATH, embeddings)
    faiss.write_index(index, str(SEMANTIC_FAISS_PATH))

    metadata = {
        "backend": "semantic",
        "doc_count": len(docs),
        "feature_count": int(embeddings.shape[1]),
        "embedding_dim": int(embeddings.shape[1]),
        "sources": {
            "ATTACK": sum(1 for doc in docs if doc.get("source") == "ATTACK"),
            "API_CHAIN": sum(1 for doc in docs if doc.get("source") == "API_CHAIN"),
            "IDA_SEMANTIC": sum(1 for doc in docs if doc.get("source") == "IDA_SEMANTIC"),
        },
        "vectorizer": model_name,
    }
    save_json(METADATA_PATH, metadata)
    return metadata


def build_and_save_index(
    max_features: int = 20000,
    backend: str = "auto",
    semantic_model: str = DEFAULT_SEMANTIC_MODEL,
    allow_model_download: bool = False,
) -> Dict[str, Any]:
    resolved = resolve_backend(backend)
    if resolved == "semantic":
        return build_semantic_index(model_name=semantic_model, allow_model_download=allow_model_download)
    return build_tfidf_index(max_features=max_features)


def ensure_index(
    backend: str = "auto",
    max_features: int = 20000,
    semantic_model: str = DEFAULT_SEMANTIC_MODEL,
    allow_model_download: bool = False,
) -> Dict[str, Any]:
    if METADATA_PATH.exists():
        metadata = load_json(METADATA_PATH)
        existing_backend = metadata.get("backend", "tfidf")
        if existing_backend == "semantic" and semantic_index_exists():
            return metadata
        if existing_backend == "tfidf" and tfidf_index_exists() and resolve_backend(backend) != "semantic":
            return metadata
    if index_exists(backend):
        return load_json(METADATA_PATH) if METADATA_PATH.exists() else {}
    return build_and_save_index(
        max_features=max_features,
        backend=backend,
        semantic_model=semantic_model,
        allow_model_download=allow_model_download,
    )


def load_tfidf_index() -> Tuple[List[Dict[str, Any]], TfidfVectorizer, sparse.csr_matrix]:
    docs = load_json(DOC_STORE_PATH)
    vectorizer = joblib.load(TFIDF_VECTORIZER_PATH)
    matrix = sparse.load_npz(TFIDF_MATRIX_PATH)
    return docs, vectorizer, matrix


def load_semantic_index() -> Tuple[List[Dict[str, Any]], Any, np.ndarray]:
    if faiss is None:
        raise RuntimeError("faiss is not installed.")
    docs = load_json(DOC_STORE_PATH)
    index = faiss.read_index(str(SEMANTIC_FAISS_PATH))
    embeddings = np.load(SEMANTIC_EMBEDDINGS_PATH)
    return docs, index, embeddings


def build_query_text(query: Dict[str, Any]) -> str:
    parts = [
        query.get("summary", ""),
        query.get("pseudocode", "")[:2000],
        " ".join(query.get("api_calls", [])),
        " ".join(query.get("strings", [])),
        " ".join(query.get("behavior_tags", [])),
        " ".join(query.get("keywords", [])),
    ]
    return "\n".join(str(part) for part in parts if part)


def keyword_overlap(query_terms: List[str], doc: Dict[str, Any]) -> Tuple[int, List[str]]:
    query_set = set(unique_strs(query_terms))
    doc_terms = set(
        unique_strs(
            doc.get("keywords", [])
            + doc.get("tags", [])
            + doc.get("attack_ids", [])
            + normalize_tokens(doc.get("title", ""))
            + normalize_tokens(doc.get("summary", ""))
        )
    )
    overlap = sorted(query_set & doc_terms)
    return len(overlap), overlap


def semantic_scores(query_text: str, metadata: Dict[str, Any]) -> np.ndarray:
    if not semantic_backend_available():
        raise RuntimeError("Semantic search requested but semantic dependencies are unavailable.")
    docs, index, _ = load_semantic_index()
    model = load_sentence_model(str(metadata.get("vectorizer", DEFAULT_SEMANTIC_MODEL)), allow_download=False)
    query_vector = model.encode(
        [query_text],
        batch_size=1,
        show_progress_bar=False,
        normalize_embeddings=True,
        convert_to_numpy=True,
    ).astype("float32")
    scores, _ = index.search(query_vector, len(docs))
    return scores[0]


def tfidf_scores(query_text: str) -> np.ndarray:
    _, vectorizer, matrix = load_tfidf_index()
    query_vector = vectorizer.transform([query_text])
    return (matrix @ query_vector.T).toarray().ravel()


def load_docs() -> List[Dict[str, Any]]:
    return load_json(DOC_STORE_PATH)


def hybrid_search(
    query: Dict[str, Any],
    top_k: int = 5,
    source_filter: str | None = None,
    exclude_doc_id: str | None = None,
    backend: str = "auto",
) -> List[Dict[str, Any]]:
    metadata = ensure_index(backend=backend)
    docs = load_docs()
    query_text = build_query_text(query)
    active_backend = metadata.get("backend", resolve_backend(backend))

    if active_backend == "semantic":
        vector_scores = semantic_scores(query_text, metadata)
    else:
        vector_scores = tfidf_scores(query_text)

    query_terms = query.get("api_calls", []) + query.get("strings", []) + query.get("behavior_tags", []) + query.get("keywords", [])

    ranked: List[Dict[str, Any]] = []
    for idx, doc in enumerate(docs):
        if source_filter and doc.get("source") != source_filter:
            continue
        if exclude_doc_id and doc.get("doc_id") == exclude_doc_id:
            continue

        overlap_count, overlap_terms = keyword_overlap(query_terms, doc)
        vector_score = float(vector_scores[idx])
        required_bonus = 0.0
        if doc.get("source") == "API_CHAIN":
            required = unique_strs(doc.get("metadata", {}).get("required_apis", []))
            optional = unique_strs(doc.get("metadata", {}).get("optional_apis", []))
            query_apis = set(query.get("api_calls", []))
            required_bonus += len(query_apis & set(required)) * 0.25
            required_bonus += len(query_apis & set(optional)) * 0.1

        hybrid_score = vector_score + overlap_count * 0.08 + required_bonus
        if hybrid_score <= 0:
            continue

        ranked.append(
            {
                "doc_id": doc["doc_id"],
                "source": doc["source"],
                "title": doc["title"],
                "summary": doc.get("summary", ""),
                "attack_ids": doc.get("attack_ids", []),
                "vector_score": round(vector_score, 6),
                "keyword_overlap": overlap_count,
                "overlap_terms": overlap_terms,
                "hybrid_score": round(hybrid_score, 6),
                "metadata": doc.get("metadata", {}),
                "backend": active_backend,
            }
        )

    ranked.sort(key=lambda item: (-item["hybrid_score"], -item["vector_score"], item["doc_id"]))
    return ranked[:top_k]
