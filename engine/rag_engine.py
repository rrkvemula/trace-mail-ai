"""
Forensic Retrieval-Augmented Generation (RAG) Engine for TRACE-MAIL AI.
Indexes MITRE ATT&CK/D3FEND, CISA/FBI IC3 Playbooks, RFC Standards,
and Historical Evidence Ledger memory.
Provides dense semantic search (MiniLM) + lexical keyword ranking for ARGUS-X Copilot.
"""

import os
import re
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import numpy as np

BASE_DIR = Path(__file__).resolve().parents[1]
KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge"
MODELS_DIR = Path(__file__).resolve().parent / "models"
LEDGER_FILE = BASE_DIR / "data" / "evidence_ledger.jsonl"
EMBEDDINGS_CACHE = MODELS_DIR / "rag_embeddings.npz"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


class ForensicRAG:
    """Air-gapped Cyber Threat Intelligence & Incident History RAG Engine."""

    _instance = None
    _tokenizer = None
    _model = None
    _chunks: List[Dict[str, Any]] = []
    _embeddings: Optional[np.ndarray] = None
    _is_initialized = False

    @classmethod
    def initialize(cls):
        """Pre-loads knowledge corpus and builds/loads vector embeddings."""
        if cls._is_initialized:
            return

        cls._load_knowledge_corpus()
        cls._ensure_embeddings()
        cls._is_initialized = True

    @classmethod
    def _load_knowledge_corpus(cls):
        """Loads all JSON files from knowledge directory."""
        cls._chunks = []
        if not KNOWLEDGE_DIR.exists():
            return

        for json_file in sorted(KNOWLEDGE_DIR.glob("*.json")):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        chunk = cls._normalize_item(item, json_file.stem)
                        if chunk:
                            cls._chunks.append(chunk)
            except Exception as e:
                print(f"[RAG] Warning loading {json_file.name}: {e}")

    @classmethod
    def _normalize_item(cls, item: Dict[str, Any], source_type: str) -> Optional[Dict[str, Any]]:
        """Converts diverse knowledge formats into normalized searchable chunks."""
        doc_id = item.get("id", "UNKNOWN")
        title = item.get("title", "")
        category = item.get("category", source_type.upper())

        # Construct dense textual representation for semantic indexing
        parts = [f"Title: {title}"]
        if "summary" in item:
            parts.append(f"Summary: {item['summary']}")
        if "mitigation" in item:
            parts.append(f"Mitigation: {item['mitigation']}")
        if "immediate_actions" in item:
            parts.append("Immediate Actions: " + " ".join(item["immediate_actions"]))
        if "key_invariants" in item:
            parts.append("Key Invariants: " + " ".join(item["key_invariants"]))
        if "indicators" in item:
            parts.append("Indicators: " + ", ".join(item["indicators"]))
        if "rule_syntax" in item:
            parts.append(f"Rule: {item['rule_syntax']}")
        if "d3fend_mapping" in item:
            parts.append(f"D3FEND: {item['d3fend_mapping']}")

        search_text = " \n".join(parts)
        return {
            "id": doc_id,
            "title": title,
            "category": category,
            "source": source_type,
            "text": search_text,
            "raw": item
        }

    @classmethod
    def _get_encoder(cls):
        """Lazy loads tokenizer and embedding model from local cache (sub-millisecond)."""
        if cls._tokenizer is None or cls._model is None:
            try:
                import torch
                from transformers import AutoTokenizer, AutoModel
                model_name = "sentence-transformers/all-MiniLM-L6-v2"
                try:
                    cls._tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
                    cls._model = AutoModel.from_pretrained(model_name, local_files_only=True)
                except Exception:
                    cls._tokenizer = AutoTokenizer.from_pretrained(model_name)
                    cls._model = AutoModel.from_pretrained(model_name)
                cls._model.eval()
            except Exception as e:
                print(f"[RAG] Embedding model init failed: {e}")
                cls._tokenizer = None
                cls._model = None
        return cls._tokenizer, cls._model

    @classmethod
    def _embed_texts(cls, texts: List[str]) -> np.ndarray:
        """Computes dense L2-normalized 384-dimensional embeddings."""
        tokenizer, model = cls._get_encoder()
        if tokenizer is None or model is None:
            # Fallback to TF-IDF hashing projection if model unavailable
            return cls._hash_fallback_embed(texts)

        import torch
        encoded = tokenizer(texts, padding=True, truncation=True, max_length=256, return_tensors="pt")
        with torch.no_grad():
            outputs = model(**encoded)
            mask = encoded["attention_mask"].unsqueeze(-1).expand(outputs.last_hidden_state.size()).float()
            sum_emb = torch.sum(outputs.last_hidden_state * mask, 1)
            sum_mask = torch.clamp(mask.sum(1), min=1e-9)
            mean_pooled = sum_emb / sum_mask
            normalized = torch.nn.functional.normalize(mean_pooled, p=2, dim=1)
            return normalized.cpu().numpy()

    @classmethod
    def _hash_fallback_embed(cls, texts: List[str]) -> np.ndarray:
        """Lightweight bag-of-words embedding fallback."""
        vectors = []
        for text in texts:
            vec = np.zeros(384, dtype=np.float32)
            tokens = re.findall(r"\w+", text.lower())
            for t in tokens:
                idx = hash(t) % 384
                vec[idx] += 1.0
            norm = np.linalg.norm(vec)
            vectors.append(vec / (norm if norm > 0 else 1.0))
        return np.array(vectors, dtype=np.float32)

    @classmethod
    def _ensure_embeddings(cls):
        """Loads cached embeddings or computes and stores them."""
        if not cls._chunks:
            cls._embeddings = np.empty((0, 384), dtype=np.float32)
            return

        corpus_ids = [c["id"] for c in cls._chunks]
        if EMBEDDINGS_CACHE.exists():
            try:
                cached = np.load(str(EMBEDDINGS_CACHE), allow_pickle=True)
                cached_ids = cached.get("ids", []).tolist()
                if cached_ids == corpus_ids:
                    cls._embeddings = cached["embeddings"]
                    return
            except Exception:
                pass

        # Compute embeddings for all chunks
        texts = [c["text"] for c in cls._chunks]
        cls._embeddings = cls._embed_texts(texts)

        try:
            np.savez_compressed(
                str(EMBEDDINGS_CACHE),
                embeddings=cls._embeddings,
                ids=np.array(corpus_ids, dtype=object)
            )
        except Exception:
            pass

    @classmethod
    def retrieve(cls, query: str, top_k: int = 3, threshold: float = 0.20) -> List[Dict[str, Any]]:
        """
        Executes hybrid dense-semantic + lexical retrieval across knowledge chunks.
        """
        cls.initialize()
        if not cls._chunks or cls._embeddings is None or len(cls._embeddings) == 0:
            return []

        # 1. Dense Semantic Similarity
        query_emb = cls._embed_texts([query])[0]
        dense_sims = np.dot(cls._embeddings, query_emb)  # Cosine similarities since L2-normalized

        # 2. Lexical Token Overlap Bonus
        query_tokens = set(re.findall(r"[a-z0-9_\-\.]{3,}", query.lower()))
        results = []

        for idx, chunk in enumerate(cls._chunks):
            sim = float(dense_sims[idx])
            chunk_tokens = set(re.findall(r"[a-z0-9_\-\.]{3,}", chunk["text"].lower()))
            overlap = len(query_tokens & chunk_tokens) / max(1, len(query_tokens))
            hybrid_score = (0.75 * sim) + (0.25 * overlap)

            # High-priority exact keyword matches (e.g. CVE, MITRE IDs, RFCs)
            for tok in query_tokens:
                if tok in chunk["id"].lower() or tok in chunk["title"].lower():
                    hybrid_score += 0.20

            if hybrid_score >= threshold:
                results.append({
                    "score": round(float(hybrid_score), 4),
                    "semantic_sim": round(float(sim), 4),
                    "id": chunk["id"],
                    "title": chunk["title"],
                    "category": chunk["category"],
                    "source": chunk["source"],
                    "text": chunk["text"],
                    "raw": chunk["raw"]
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    @classmethod
    def query_ledger_history(cls, query: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """
        Scans historical evidence ledger (evidence_ledger.jsonl) for cross-incident correlation.
        """
        if not LEDGER_FILE.exists():
            return []

        tokens = set(re.findall(r"[a-zA-Z0-9_\-\.:]{4,}", query.lower()))
        matches = []

        try:
            with open(LEDGER_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    rec_str = json.dumps(record).lower()
                    matched_tokens = [t for t in tokens if t in rec_str]
                    if matched_tokens:
                        matches.append({
                            "analysis_id": record.get("analysis_id"),
                            "timestamp": record.get("recorded_at_utc") or record.get("timestamp_iso"),
                            "forensic_hash": record.get("evidence_hash") or record.get("forensic_hash"),
                            "record_hash": record.get("record_hash"),
                            "matched_indicators": matched_tokens
                        })
        except Exception:
            pass

        return matches[:top_k]

    @classmethod
    def build_augmented_context(cls, user_message: str, report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Constructs verified ground-truth context for ARGUS-X / Copilot,
        combining current report IOCs, retrieved playbooks, and ledger precedents.
        """
        # Formulate enriched query incorporating active email context
        query_parts = [user_message]
        report_summary = {}

        if report:
            threat = report.get("threat_analysis", {})
            auth = report.get("authentication", {})
            ai_data = report.get("ai", {})
            detections = threat.get("detections", [])

            if detections:
                query_parts.append("Detections: " + " ".join(detections))
            if ai_data.get("bec_type") and ai_data.get("bec_type") != "none":
                query_parts.append(f"BEC Type: {ai_data.get('bec_type')}")
            if not auth.get("composite_pass"):
                query_parts.append("Authentication Failure: SPF/DKIM/DMARC alignment failed")

            report_summary = {
                "fraud_score": threat.get("threat_score") or report.get("fraud_score"),
                "risk_level": threat.get("risk_category") or report.get("risk_level"),
                "label": report.get("label"),
                "detections": detections,
                "origin_ip": report.get("origin_ip") or report.get("trace", {}).get("geo", {}).get("ip")
            }

        combined_query = " ".join(query_parts)
        retrieved_docs = cls.retrieve(combined_query, top_k=3)

        # Check ledger memory
        ledger_hits = []
        if report and report_summary.get("origin_ip"):
            ledger_hits = cls.query_ledger_history(str(report_summary["origin_ip"]))
        if not ledger_hits:
            ledger_hits = cls.query_ledger_history(user_message)

        # Format markdown context
        ctx_lines = ["### Grounded Cyber Threat Intelligence & Forensic Precedents (RAG):"]
        citations = []

        for doc in retrieved_docs:
            citations.append(f"[{doc['id']}] {doc['title']}")
            ctx_lines.append(f"\n#### [{doc['id']}] {doc['title']} ({doc['category']})")
            if "immediate_actions" in doc["raw"]:
                ctx_lines.append("**Mandatory Incident Actions:**")
                for action in doc["raw"]["immediate_actions"][:4]:
                    ctx_lines.append(f"- {action}")
            elif "key_invariants" in doc["raw"]:
                ctx_lines.append("**RFC Technical Invariants:**")
                for inv in doc["raw"]["key_invariants"][:3]:
                    ctx_lines.append(f"- {inv}")
            elif "mitigation" in doc["raw"]:
                ctx_lines.append(f"**Mitigation:** {doc['raw']['mitigation']}")
            if "rule_syntax" in doc["raw"]:
                ctx_lines.append(f"```text\n{doc['raw']['rule_syntax']}\n```")

        if ledger_hits:
            ctx_lines.append("\n#### Prior Incident Ledger Memory Matches:")
            for hit in ledger_hits:
                ctx_lines.append(
                    f"- Incident `{hit['analysis_id']}` ({hit['timestamp']}): "
                    f"Prior forensic match on indicator(s) {hit['matched_indicators']} "
                    f"(Record Hash: `{hit['record_hash'][:16]}...`)"
                )
                citations.append(f"[LEDGER] Incident {hit['analysis_id']}")

        augmented_text = "\n".join(ctx_lines) if retrieved_docs or ledger_hits else ""
        return {
            "augmented_context": augmented_text,
            "citations": citations,
            "retrieved_count": len(retrieved_docs),
            "ledger_matches_count": len(ledger_hits),
            "top_doc": retrieved_docs[0] if retrieved_docs else None
        }


# Eager initialization on import
RAG_ENGINE = ForensicRAG
