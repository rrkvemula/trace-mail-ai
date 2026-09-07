"""Builds a compact evidence relationship graph for one analyzed email."""

import re
from urllib.parse import urlparse
from typing import Any, Dict, List


class IOCGraphBuilder:
    @staticmethod
    def _domain(value: str) -> str:
        match = re.search(r"@([A-Za-z0-9._-]+)", value or "")
        return match.group(1).lower().rstrip(">") if match else ""

    @classmethod
    def build(cls, parsed: Dict[str, Any], analyzed_hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        root_id = f"email:{parsed.get('forensic_hash', '')[:12]}"
        nodes = [{"id": root_id, "type": "EMAIL", "label": "Submitted email"}]
        edges = []
        seen = {root_id}

        def add_node(node_id: str, node_type: str, label: str, relation: str):
            if not node_id or node_id == f"{node_type.lower()}:":
                return
            if node_id not in seen:
                nodes.append({"id": node_id, "type": node_type, "label": label})
                seen.add(node_id)
            edges.append({"source": root_id, "target": node_id, "relation": relation})

        headers = parsed.get("headers", {})
        for field in ("from", "reply_to", "return_path"):
            domain = cls._domain(headers.get(field, ""))
            if domain:
                add_node(f"domain:{domain}", "DOMAIN", domain, field.upper())

        for hop in analyzed_hops:
            ip = hop.get("ip")
            if ip:
                add_node(f"ip:{ip}", "IP", ip, f"RELAY_HOP_{hop.get('hop_number')}")

        for link in parsed.get("body", {}).get("links", []):
            normalized = link if "://" in link else f"http://{link}"
            host = (urlparse(normalized).hostname or "").lower()
            if host:
                add_node(f"url-domain:{host}", "URL_DOMAIN", host, "EMBEDDED_LINK")

        for attachment in parsed.get("attachments", []):
            digest = attachment.get("sha256")
            if digest:
                add_node(f"attachment:{digest[:16]}", "ATTACHMENT", attachment.get("filename", "attachment"), "ATTACHMENT")

        counts = {}
        for node in nodes:
            counts[node["type"]] = counts.get(node["type"], 0) + 1
        return {"nodes": nodes, "edges": edges, "counts": counts, "scope": "SINGLE_EMAIL_EVIDENCE_GRAPH"}
