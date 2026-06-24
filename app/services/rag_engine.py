"""Retrieval-Augmented Generation engine for SOC knowledge base."""

from pathlib import Path
from typing import Optional

from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.config import KNOWLEDGE_BASE_DIR, settings


class RAGEngine:
    """Manages vector store and retrieval for MITRE, NIST, and threat intel."""

    def __init__(self):
        self._vectorstore: Optional[Chroma] = None
        self._llm: Optional[ChatOpenAI] = None
        self._embeddings: Optional[OpenAIEmbeddings] = None

    @property
    def is_ready(self) -> bool:
        persist_dir = Path(settings.chroma_persist_dir)
        return persist_dir.exists() and any(persist_dir.iterdir())

    def _get_embeddings(self) -> OpenAIEmbeddings:
        if not self._embeddings:
            self._embeddings = OpenAIEmbeddings(
                model=settings.openai_embedding_model,
                openai_api_key=settings.openai_api_key,
            )
        return self._embeddings

    def _get_llm(self) -> ChatOpenAI:
        if not self._llm:
            self._llm = ChatOpenAI(
                model=settings.openai_model,
                openai_api_key=settings.openai_api_key,
                temperature=0.1,
            )
        return self._llm

    def _load_documents(self) -> list[Document]:
        documents: list[Document] = []
        for subdir in ["mitre_attack", "nist", "threat_intel"]:
            path = KNOWLEDGE_BASE_DIR / subdir
            if path.exists():
                loader = DirectoryLoader(
                    str(path),
                    glob="**/*.md",
                    loader_cls=TextLoader,
                    loader_kwargs={"encoding": "utf-8"},
                )
                docs = loader.load()
                for doc in docs:
                    doc.metadata["source_category"] = subdir
                documents.extend(docs)
        return documents

    def ingest(self) -> int:
        """Load knowledge base and build vector store. Returns document count."""
        documents = self._load_documents()
        if not documents:
            raise ValueError("No documents found in knowledge base")

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,
            chunk_overlap=150,
            separators=["\n## ", "\n### ", "\n", " "],
        )
        chunks = splitter.split_documents(documents)

        persist_dir = Path(settings.chroma_persist_dir)
        persist_dir.mkdir(parents=True, exist_ok=True)

        self._vectorstore = Chroma.from_documents(
            documents=chunks,
            embedding=self._get_embeddings(),
            persist_directory=str(persist_dir),
            collection_name="soc_knowledge",
        )
        return len(chunks)

    def _load_vectorstore(self) -> Chroma:
        if self._vectorstore is None:
            self._vectorstore = Chroma(
                persist_directory=settings.chroma_persist_dir,
                embedding_function=self._get_embeddings(),
                collection_name="soc_knowledge",
            )
        return self._vectorstore

    def retrieve(self, query: str, top_k: Optional[int] = None) -> list[Document]:
        """Retrieve relevant knowledge base chunks."""
        if not self.is_ready:
            return self._fallback_retrieve(query)

        k = top_k or settings.retrieval_top_k
        store = self._load_vectorstore()
        return store.similarity_search(query, k=k)

    def _fallback_retrieve(self, query: str) -> list[Document]:
        """Keyword-based fallback when vector store is unavailable."""
        query_lower = query.lower()
        results: list[tuple[int, Document]] = []

        for md_file in KNOWLEDGE_BASE_DIR.rglob("*.md"):
            content = md_file.read_text(encoding="utf-8")
            score = sum(1 for word in query_lower.split() if word in content.lower())
            if score > 0:
                category = md_file.parent.name
                results.append((score, Document(
                    page_content=content[:1500],
                    metadata={"source": str(md_file), "source_category": category},
                )))

        results.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in results[: settings.retrieval_top_k]]

    def query_with_context(self, alert_text: str) -> tuple[str, list[str]]:
        """Retrieve context and generate analysis using RAG."""
        docs = self.retrieve(alert_text)
        context_snippets = [
            f"[{d.metadata.get('source_category', 'unknown')}] {d.page_content[:500]}"
            for d in docs
        ]
        context_block = "\n\n---\n\n".join(context_snippets)

        if not settings.has_openai_key:
            return self._fallback_analysis(alert_text, context_snippets), context_snippets

        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an expert Tier-1 SOC analyst assistant. Analyze the security alert using the provided context from MITRE ATT&CK, NIST guidance, and threat intelligence.

Provide:
1. A concise executive summary (2-3 sentences)
2. Severity assessment (critical/high/medium/low/informational) with justification
3. Key findings and attack chain analysis
4. Specific remediation recommendations mapped to NIST incident response phases

Be precise, actionable, and reference MITRE technique IDs where applicable."""),
            ("human", "Security Alert:\n{alert}\n\nKnowledge Base Context:\n{context}"),
        ])

        chain = prompt | self._get_llm()
        response = chain.invoke({"alert": alert_text, "context": context_block})
        return response.content, context_snippets

    def _fallback_analysis(self, alert_text: str, context_snippets: list[str]) -> str:
        """Rule-based analysis when OpenAI is not configured."""
        severity = "medium"
        alert_lower = alert_text.lower()
        if any(kw in alert_lower for kw in ["ransomware", "lockbit", "cobalt strike", "critical"]):
            severity = "critical"
        elif any(kw in alert_lower for kw in ["powershell", "encoded", "beacon", "high"]):
            severity = "high"

        return f"""## Alert Analysis (Offline Mode)

**Severity:** {severity.upper()}

**Summary:** Security alert detected requiring analyst review. Automated analysis performed using rule-based classification and knowledge base keyword matching. Configure OPENAI_API_KEY for full AI-powered analysis.

**Context Sources Used:** {len(context_snippets)} knowledge base document(s) retrieved.

**Recommended Actions:**
1. Validate alert authenticity and eliminate false positives
2. Extract and block identified IOCs at perimeter controls
3. Isolate affected hosts if malicious activity is confirmed
4. Escalate to Tier-2 for deeper forensic analysis
5. Document findings per NIST SP 800-61 incident handling procedures
"""


# Singleton instance
rag_engine = RAGEngine()
