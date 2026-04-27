import argparse

try:
    from .rag_index import DEFAULT_SEMANTIC_MODEL, build_and_save_index
except ImportError:
    from rag_index import DEFAULT_SEMANTIC_MODEL, build_and_save_index


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build local RAG vector index for ATT&CK/API_CHAIN/IDA_SEMANTIC rag docs.")
    parser.add_argument("--max-features", type=int, default=20000, help="Maximum TF-IDF vocabulary size")
    parser.add_argument("--backend", choices=["auto", "tfidf", "semantic"], default="auto", help="Index backend")
    parser.add_argument("--semantic-model", default=DEFAULT_SEMANTIC_MODEL, help="SentenceTransformer model name")
    parser.add_argument("--allow-model-download", action="store_true", help="Allow downloading semantic model files")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    metadata = build_and_save_index(
        max_features=max(1000, args.max_features),
        backend=args.backend,
        semantic_model=args.semantic_model,
        allow_model_download=args.allow_model_download,
    )
    print("[+] RAG vector index built.")
    print(f"    Backend      : {metadata.get('backend', 'unknown')}")
    print(f"    Doc count    : {metadata.get('doc_count', 0)}")
    print(f"    Feature count: {metadata.get('feature_count', 0)}")
    print(f"    Sources      : {metadata.get('sources', {})}")


if __name__ == "__main__":
    main()
