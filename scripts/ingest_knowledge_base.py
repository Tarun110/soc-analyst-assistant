"""Script to ingest MITRE, NIST, and threat intel into vector store."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings
from app.services.rag_engine import rag_engine


def main():
    if not settings.has_openai_key:
        print("ERROR: Set OPENAI_API_KEY in .env before ingesting.")
        print("Copy .env.example to .env and add your API key.")
        sys.exit(1)

    print("Ingesting knowledge base...")
    count = rag_engine.ingest()
    print(f"Done. Ingested {count} document chunks into {settings.chroma_persist_dir}")


if __name__ == "__main__":
    main()
