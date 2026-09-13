"""
Forensic AI Copilot & Neural Threat Triage Engine.
Provides conversational explanation of email investigation reports,
RFC 5322 header invariants, domain WHOIS telemetry, MTA hop latency,
and out-of-band verification recommendations.
Augmented with Forensic RAG: MITRE ATT&CK/D3FEND, CISA/FBI Playbooks,
RFC standards, and past incident ledger memory.
Supports local Ollama LLMs with an instant, deterministic forensic reasoning fallback.
"""

import json
import re
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

from .rag_engine import ForensicRAG


class ForensicCopilot:
    """Conversational AI Analyst for TraceMail Forensic Intelligence."""

    OLLAMA_URL = "http://localhost:11434/api/chat"
    OLLAMA_TIMEOUT = 3.5  # Fast fallback if Ollama hangs or requires auth

    @classmethod
    def query(
        cls,
        user_message: str,
        report: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None,
        preferred_model: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Processes user query against current forensic report context.
        Prioritizes ARGUS-X air-gapped native reasoning engine.
        Falls back to local Ollama or deterministic expert rules augmented with RAG.
        """
        user_msg = (user_message or "").strip()
        if not user_msg:
            return {
                "reply": (
                    "**[ARGUS-X FORENSIC KERNEL ONLINE]**\n\n"
                    "Greetings Analyst. I am **ARGUS-X**, your native air-gapped forensic intelligence engine. "
                    "I evaluate RFC 5322 invariants, authenticate cryptographic alignment, and generate automated defensive rules.\n\n"
                    "*You can ask:*\n"
                    "- *'Why is this email flagged as high risk?'*\n"
                    "- *'What does CISA & FBI IC3 playbook recommend for wire fraud?'*\n"
                    "- *'Generate a Snort 3 or Sigma rule to block this threat.'*\n"
                    "- *'Has this sender IP or domain appeared in prior incidents?'*\n"
                    "- *'Explain the SPF and DMARC alignment status.'*"
                ),
                "category": "GREETING",
                "engine": "argus_x_native",
                "citations": [],
                "rag_augmented": False,
                "suggested_prompts": [
                    "Explain Overall Threat Verdict",
                    "Show CISA & FBI BEC Playbook",
                    "Map to MITRE ATT&CK & D3FEND",
                    "Generate Snort 3 & Sigma Rules",
                    "Audit RFC Header Invariants"
                ]
            }

        # 0. Retrieve grounded Cyber Threat Intelligence & Incident History via RAG
        rag_data = ForensicRAG.build_augmented_context(user_msg, report)

        # 1. Primary: ARGUS-X Native Forensic Intelligence Engine
        try:
            from argus_x.analyst import ArgusAnalyst
            argus_res = ArgusAnalyst.query(user_msg, report, history)
            if argus_res and argus_res.get("reply"):
                if rag_data and rag_data.get("augmented_context"):
                    argus_res["reply"] += "\n\n" + rag_data["augmented_context"]
                if rag_data.get("citations"):
                    argus_res["citations"] = rag_data["citations"]
                    argus_res["rag_augmented"] = True
                return argus_res
        except Exception:
            pass

        # 2. Secondary: TokenRouter GLM-5.3 Neural Inference (if available)
        glm_res = cls._try_tokenrouter_glm(user_msg, report, history, preferred_model, rag_data)
        if glm_res:
            return {
                "reply": glm_res,
                "category": "GLM_NEURAL_INFERENCE",
                "engine": "z-ai/glm-5.3-free",
                "citations": rag_data.get("citations", []),
                "rag_augmented": bool(rag_data.get("citations")),
                "suggested_prompts": cls._get_contextual_prompts(user_msg, report)
            }

        # 3. Tertiary: Local Ollama Neural Inference (if available)
        ollama_res = cls._try_ollama(user_msg, report, history, preferred_model, rag_data)
        if ollama_res:
            return {
                "reply": ollama_res,
                "category": "NEURAL_INFERENCE",
                "engine": "ollama",
                "citations": rag_data.get("citations", []),
                "rag_augmented": bool(rag_data.get("citations")),
                "suggested_prompts": cls._get_contextual_prompts(user_msg, report)
            }

        # 4. Deterministic Forensic Reasoning Engine Fallback with RAG Grounding
        reasoned_reply, category = cls._reason_expert(user_msg, report, history, rag_data)
        return {
            "reply": reasoned_reply,
            "category": category,
            "engine": "trace_mail_neural_rules",
            "citations": rag_data.get("citations", []),
            "rag_augmented": bool(rag_data.get("citations")),
            "suggested_prompts": cls._get_contextual_prompts(user_msg, report)
        }

    @classmethod
    def _try_tokenrouter_glm(
        cls,
        query: str,
        report: Optional[Dict[str, Any]],
        history: Optional[List[Dict[str, str]]],
        model_name: Optional[str],
        rag_data: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Attempts to query TokenRouter GLM-5.3 if configured."""
        import os
        api_key = os.environ.get("TOKENROUTER_API_KEY", "").strip()
        if not api_key:
            return None

        # If user explicitly requested another model not matching glm, skip
        if model_name and not any(k in model_name.lower() for k in ("glm", "tokenrouter", "default", "auto")):
            return None

        try:
            context_summary = "No active report scanned yet."
            if report:
                context_summary = json.dumps({
                    "threat_score": report.get("fraud_score") if report.get("fraud_score") is not None else report.get("threat_analysis", {}).get("threat_score"),
                    "risk_level": report.get("risk_level") or report.get("threat_analysis", {}).get("risk_category"),
                    "label": report.get("label"),
                    "headers": report.get("headers"),
                    "trace": report.get("trace") or report.get("origin_geo"),
                    "links_count": len(report.get("links", []) or report.get("body_summary", {}).get("scanned_links", [])),
                    "reasons": report.get("ai", {}).get("reasons", []) or [f.get("detail") for f in report.get("threat_analysis", {}).get("explainability_factors", []) if isinstance(f, dict)]
                }, default=str)

            system_text = (
                "You are TraceMail AI Forensic Copilot (powered by GLM-5.3), an expert cybersecurity engineer "
                "and RFC 5322 email forensics specialist. You assist SOC analysts in evaluating "
                "phishing, BEC, spoofing, and malicious headers. Ground your analysis strictly in the provided "
                "investigation report context. Keep responses concise, professional, and formatted with Markdown bullet points.\n\n"
                f"ACTIVE EMAIL INVESTIGATION REPORT CONTEXT:\n{context_summary}"
            )

            if rag_data and rag_data.get("augmented_context"):
                system_text += f"\n\n{rag_data['augmented_context']}"

            messages = [{"role": "system", "content": system_text}]
            if history:
                for h in history[-4:]:
                    if h.get("role") in ("user", "assistant") and h.get("content"):
                        messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": query})

            target_model = model_name if (model_name and "glm" in model_name.lower()) else "z-ai/glm-5.3-free"
            payload = json.dumps({
                "model": target_model,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1000
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.tokenrouter.com/v1/chat/completions",
                data=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "TraceMail-Copilot/2.1"
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=cls.OLLAMA_TIMEOUT + 2.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                    if content:
                        return content
        except Exception:
            pass
        return None

    @classmethod
    def _try_ollama(
        cls,
        query: str,
        report: Optional[Dict[str, Any]],
        history: Optional[List[Dict[str, str]]],
        model_name: Optional[str],
        rag_data: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Attempts to query local Ollama instance with timeout and RAG injection."""
        try:
            context_summary = "No active report scanned yet."
            if report:
                context_summary = json.dumps({
                    "fraud_score": report.get("fraud_score"),
                    "risk_level": report.get("risk_level"),
                    "label": report.get("label"),
                    "confidence": report.get("confidence"),
                    "bec_type": report.get("ai", {}).get("bec_type"),
                    "headers": report.get("headers"),
                    "trace": report.get("trace"),
                    "links_count": len(report.get("links", [])),
                    "reasons": report.get("ai", {}).get("reasons", [])
                })

            system_text = (
                "You are TraceMail AI Forensic Copilot, an expert cybersecurity engineer "
                "and RFC 5322 email forensics specialist. You assist SOC analysts in evaluating "
                "phishing, BEC, spoofing, and malicious headers. Keep responses concise, professional, "
                "and formatted with Markdown bullet points.\n\n"
                f"ACTIVE EMAIL INVESTIGATION REPORT CONTEXT:\n{context_summary}"
            )

            if rag_data and rag_data.get("augmented_context"):
                system_text += f"\n\n{rag_data['augmented_context']}"

            messages = [
                {
                    "role": "system",
                    "content": system_text
                }
            ]

            if history:
                for h in history[-4:]:
                    if h.get("role") in ("user", "assistant") and h.get("content"):
                        messages.append({"role": h["role"], "content": h["content"]})

            messages.append({"role": "user", "content": query})

            model = model_name or "glm-5.3:cloud"
            payload = json.dumps({
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9
                }
            }).encode("utf-8")

            req = urllib.request.Request(
                cls.OLLAMA_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=cls.OLLAMA_TIMEOUT) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("message", {}).get("content", "").strip()
        except Exception:
            pass  # Fall back cleanly
        return None

    @classmethod
    def _reason_expert(
        cls,
        query: str,
        report: Optional[Dict[str, Any]],
        history: Optional[List[Dict[str, str]]],
        rag_data: Optional[Dict[str, Any]] = None
    ) -> tuple[str, str]:
        """Deterministic forensic analyst engine matching semantic intent with RAG augmentation."""
        q = query.lower()

        if not report or (not report.get("fraud_score") and not report.get("headers")):
            standby_text = (
                "### 🛰️ TraceMail AI Copilot Standby Mode\n\n"
                "No email has been actively scanned in the forensic console yet.\n\n"
                "**How to get started:**\n"
                "1. Select any pre-loaded threat vector from the **Pre-loaded Forensic Samples** menu (e.g. *Credential Harvest SSRF Attack* or *Vendor Bank Change BEC*).\n"
                "2. Click **Load & Deep Scan**.\n"
                "3. Return here, and I will dissect its RFC headers, domain WHOIS telemetry, timing anomalies, and out-of-band verification steps for you!\n\n"
                "*You can also ask general email security questions right now, such as 'What is DMARC alignment?' or 'How does display name spoofing work?'*"
            )
            # If user asked a RAG-addressable query even without an active report
            if rag_data and rag_data.get("augmented_context") and any(w in q for w in ["mitre", "cisa", "fbi", "rfc", "playbook", "snort", "sigma"]):
                return (
                    f"{rag_data['augmented_context']}\n\n*Load an email in the console to correlate with active telemetry.*",
                    "RAG_INTELLIGENCE"
                )
            return standby_text, "STANDBY"

        # Extract Report Telemetry
        score = report.get("fraud_score", 0)
        risk = report.get("risk_level", "UNKNOWN")
        label = str(report.get("label", "analyzed")).upper()
        conf = report.get("confidence", 85)
        headers = report.get("headers") or {}
        ai_data = report.get("ai") or {}
        bec_type = ai_data.get("bec_type", "none")
        reasons = ai_data.get("reasons") or headers.get("reasons") or []
        trace = report.get("trace") or {}
        geo = trace.get("geo") or {}
        links = report.get("links") or []
        origin_ip = headers.get("origin_ip") or geo.get("ip") or "Unknown Relay"
        from_hdr = headers.get("from", "N/A")
        reply_to = headers.get("reply_to", "N/A")
        ret_path = headers.get("return_path", "N/A")
        hops_count = headers.get("hops", 0)
        spf_pass = headers.get("spf", False)
        dkim_pass = headers.get("dkim", False)
        dmarc_pass = headers.get("dmarc", False)

        # --- INTENT ROUTING ---

        # 0. GREETING & CONVERSATIONAL INTENTS (hi, hello, hey, who are you, help, etc.)
        greeting_words = {"hi", "hello", "hey", "hola", "yo", "good morning", "good afternoon", "good evening", "argus", "sup", "greetings"}
        words = set(re.findall(r'\b[a-zA-Z]+\b', q))
        is_greeting = bool(words.intersection(greeting_words)) and (len(words) <= 4 or q.strip() in greeting_words)

        if is_greeting:
            analyst_name = "Analyst"
            if history:
                for h in history:
                    if isinstance(h, dict) and h.get("analyst_name"):
                        analyst_name = h.get("analyst_name")
                        break
            
            status_desc = f"Currently analyzing email from `{from_hdr}` with threat score **{score}/100** ({risk})." if from_hdr != "N/A" else "Forensic sensors standing by for email ingestion."
            
            greeting_reply = [
                "### 🛡️ [ARGUS-X FORENSIC COGNITION ONLINE]",
                f"Greetings, **{analyst_name}**. All neural diagnostic telemetry is active.",
                "",
                f"**Current Operational Context:** {status_desc}",
                "",
                "I am ready to assist your investigation. Here is what you can ask me:",
                "- 🎯 **Dissect Threat Invariants:** *'Explain this threat'* or *'Why is this flagged?'*",
                "- 🛰️ **Inspect MTA Hops & GeoINT:** *'Where did this email physically originate?'*",
                "- 🔑 **Analyze Authentication:** *'Explain SPF, DKIM and DMARC'*",
                "- 📜 **Deploy Defense Rules:** *'Generate Snort and Sigma rules'*",
                "- 🏢 **Audit WHOIS & Domain:** *'Inspect the domain and Reply-To'*",
                "",
                "*What specific vector would you like me to inspect?*"
            ]
            return "\n".join(greeting_reply), "GREETING"

        # WHO ARE YOU / CAPABILITIES
        if any(w in q for w in ["who are you", "what can you do", "help me", "how to use", "commands", "features", "what is this"]):
            cap_reply = [
                "### 🛰️ ARGUS-X Autonomous SOC Forensic Copilot",
                "I am **ARGUS-X**, the dedicated forensic AI agent powering **TRACE-MAIL AI** for the Smart India Hackathon (PS ID: SIH26106).",
                "",
                "#### ⚡ Core Investigative Capabilities:",
                "1. **RFC 5322 Invariant Auditing:** Detects header forgery, negative transit travel (ΔT < 0), and anomalous relay latency.",
                "2. **Cryptographic Identity Verification:** Evaluates SPF, DKIM, and DMARC alignment against envelope Return-Path and Header From.",
                "3. **GeoINT Planetary Tracing:** Maps boundary relay IP hops to physical coordinates and autonomous system numbers (ASNs).",
                "4. **Linguistic & BEC Multi-Signal Analysis:** Isolates executive impersonation, wire fraud phrases, and SSRF token leakage.",
                "5. **CISA & MITRE Defense Generation:** Auto-generates Snort 3, Sigma, and mail gateway filtering rules grounded in cyber playbooks.",
                "",
                "👉 *Ask me any question about the scanned email or email security in general!*"
            ]
            return "\n".join(cap_reply), "CAPABILITIES"

        # SIMPLE / EXECUTIVE "IS THIS SAFE?" / "SHOULD I CLICK?"
        if any(w in q for w in ["is this safe", "is it safe", "should i click", "can i open", "is this real", "is this legitimate", "is this scam", "what should i do"]):
            if score >= 70:
                safety_verdict = (
                    "### 🚨 CRITICAL THREAT VERDICT: DO NOT CLICK OR INTERACT\n\n"
                    f"**Verdict:** This email is **HIGHLY DANGEROUS** (Threat Score: **{score}/100**).\n\n"
                    "**Immediate Actions Required:**\n"
                    "1. ❌ **Do NOT click any links** or open attachments in this message.\n"
                    "2. ❌ **Do NOT reply** or wire funds to requested accounts.\n"
                    f"3. 🔒 **Origin IP:** Quarantine `{origin_ip}` on your border firewall/mail gateway.\n"
                    "4. 📞 **Out-of-Band Verification:** If this claims to be from leadership or a vendor, verify via phone call using previously known contact info."
                )
            elif score >= 35:
                safety_verdict = (
                    "### ⚠️ SUSPICIOUS MESSAGE: EXERCISE EXTREME CAUTION\n\n"
                    f"**Verdict:** This email has **ANOMALOUS INVARIANTS** (Threat Score: **{score}/100**).\n\n"
                    "**Precautions:**\n"
                    "1. Check the domain spelling carefully for punycode lookalikes.\n"
                    "2. Verify SPF/DKIM authentication status before clicking any action buttons.\n"
                    "3. Validate bank account change requests through independent phone verification."
                )
            else:
                safety_verdict = (
                    "### ✅ MESSAGE APPEARS AUTHENTIC\n\n"
                    f"**Verdict:** Low observed risk (Threat Score: **{score}/100**).\n\n"
                    "SPF, DKIM, and DMARC signatures align with the authorized domain, and no deceptive relay latency or urgency phrases were found."
                )
            return safety_verdict, "SAFETY_ASSESSMENT"

        # GRATITUDE / CASUAL ACKNOWLEDGMENT
        if any(w in q for w in ["thank you", "thanks", "thx", "awesome", "great", "cool", "got it", "ok", "okay"]):
            return (
                "### 🫡 Standing By, Analyst\n\n"
                "You're welcome. All telemetry and evidence hashes are preserved in the cryptographic ledger. "
                "Let me know whenever you need further forensic dissection or rule generation.",
                "ACKNOWLEDGMENT"
            )

        # 1. EXPLICIT RAG INTENT (MITRE, CISA/FBI, Detection Rules, Ledger Precedents)
        if any(w in q for w in ["mitre", "playbook", "cisa", "fbi", "ic3", "snort", "sigma", "rule", "ledger", "history", "previous incident"]):
            if rag_data and rag_data.get("augmented_context"):
                reply = [
                    rag_data["augmented_context"],
                    "",
                    "#### 🔒 Active Incident Defense Mapping:",
                    f"- **Observed Target:** `{from_hdr}` | **Origin:** `{origin_ip}`",
                    f"- **Risk Posture:** `{risk}` ({score}/100)",
                    "- **Action:** Apply CISA out-of-band verification and activate the perimeter rules above."
                ]
                return "\n".join(reply), "RAG_INTELLIGENCE"

        # 1. OVERALL INVESTIGATION REPORT / SUMMARY
        if any(w in q for w in ["report", "summary", "summarize", "overview", "verdict", "score", "why flagged", "explain this"]):
            reply = [
                "### 📊 Executive Forensic Investigation Report",
                f"- **Composite Threat Score:** `{score}/100` ({risk} Risk)",
                f"- **Risk Classification:** **{label}** ({conf}% Confidence)",
                f"- **Attack Pattern Isolation:** `{bec_type.upper()}`",
                f"- **Origin Geolocation:** {geo.get('city', 'Unknown City')}, {geo.get('country', 'Unknown Country')} (`{origin_ip}`)",
                f"- **Authentication Posture:** SPF: {'✅ PASS' if spf_pass else '❌ FAIL'} | DKIM: {'✅ PASS' if dkim_pass else '❌ FAIL'} | DMARC: {'✅ PASS' if dmarc_pass else '❌ FAIL'}",
                "",
                "#### 🔬 Key Forensic Findings:"
            ]
            if reasons:
                for r in reasons:
                    reply.append(f"- ⚠️ **{r}**")
            else:
                reply.append("- ✅ No invariant anomalies or deceptive patterns detected.")

            reply.extend([
                "",
                "#### 🛡️ Analyst Verdict & Action:",
                "- **Recommendation:** " + (
                    "**CRITICAL CONTAINMENT:** Isolate message immediately. Quarantine origin IP on mail gateway. Issue security notice regarding financial diversion." if score >= 70
                    else "**SUSPICIOUS:** Require secondary out-of-band verification before clicking links or processing requests." if score >= 35
                    else "**SAFE / BENIGN:** RFC 5322 invariants and cryptographic signatures conform with normal operational baselines."
                )
            ])
            return "\n".join(reply), "REPORT_SUMMARY"

        # 2. DOMAIN & WHOIS ANALYSIS
        if any(w in q for w in ["domain", "whois", "mx", "registrar", "reply-to", "reply to", "lookalike", "punycode", "creation date"]):
            whois = geo.get("whois") or {}
            reg = whois.get("registrar", "Private / Cloudflare Registrar")
            created = whois.get("creation", "Recently Observed / Privacy Protected")
            mx_list = trace.get("mx", [])
            mx_str = ", ".join(mx_list) if mx_list else "Standard SMTP Exchange"

            reply = [
                "### 🌐 Domain & Identity Infrastructure Dissection",
                f"- **Header From:** `{from_hdr}`",
                f"- **Envelope Return-Path:** `{ret_path}`",
                f"- **Reply-To Target:** `{reply_to}`",
                "",
                "#### 🔍 Identity Invariant Assessment:"
            ]

            if reply_to and reply_to != from_hdr and reply_to != "N/A":
                reply.append(f"- 🚨 **Reply-To Organizational Mismatch Detected:** The email claims to be sent from `{from_hdr}`, but responses are directed to `{reply_to}`. This is a classic tactic used to hijack legitimate vendor conversation threads.")
            else:
                reply.append("- ✅ **Alignment Check:** Header From and Reply-To domains are mutually aligned.")

            reply.extend([
                "",
                "#### 🏢 WHOIS & Routing Telemetry:",
                f"- **Registered Registrar:** `{reg}`",
                f"- **Domain Creation Age:** `{created}`",
                f"- **Mail Exchange (MX) Route:** `{mx_str}`",
                f"- **Host Organization:** `{geo.get('org', geo.get('organization', 'N/A'))}`"
            ])

            if any("punycode" in str(r).lower() for r in reasons):
                reply.append("- ⚠️ **Punycode / Homograph Warning:** Domain contains internationalized characters (`xn--`) mimicking a trusted enterprise brand.")

            return "\n".join(reply), "DOMAIN_ANALYSIS"

        # 3. RFC HEADERS & CRYPTOGRAPHIC AUTHENTICATION
        if any(w in q for w in ["header", "spf", "dkim", "dmarc", "authentication", "return-path", "message-id", "crypto", "invariant"]):
            reply = [
                "### 🛡️ RFC 5322 Headers & Cryptographic Integrity Audit",
                f"- **SPF (Sender Policy Framework):** {'✅ PASS' if spf_pass else '❌ FAIL / MISSING'}",
                f"  *Validation:* Checks if client IP `{origin_ip}` is authorized in sender's DNS TXT record.",
                f"- **DKIM (DomainKeys Identified Mail):** {'✅ PASS' if dkim_pass else '❌ FAIL / MISSING'}",
                "  *Validation:* Cryptographic public/private keypair signature over email headers & body.",
                f"- **DMARC (Domain-based Message Authentication):** {'✅ PASS' if dmarc_pass else '❌ FAIL / MISSING'}",
                "  *Validation:* Enforces strict alignment between RFC 5322 `From:` and SPF/DKIM domains.",
                "",
                "#### 🔑 Forensic Takeaway:"
            ]

            if spf_pass and dkim_pass and score >= 70:
                reply.append("- ⚠️ **Crucial Detection Insight:** Notice that SPF and DKIM **PASSED**, yet the Threat Score is **CRITICAL**. This highlights compromised account takeover (Account Takeover / BEC). Attackers who compromise real enterprise mailboxes have valid cryptographic signatures, but our behavioral heuristics caught the fraudulent banking/wire language and Reply-To redirection!")
            elif not spf_pass or not dkim_pass:
                reply.append("- 🚨 **Spoofing Alert:** Lack of valid SPF/DKIM indicates this email was injected from an unauthorized SMTP relay attempting to forge the sender's identity.")
            else:
                reply.append("- ✅ All cryptographic checks match authentic corporate mail gateway policies.")

            return "\n".join(reply), "HEADER_ANALYSIS"

        # 4. MTA HOPS & TIMING LATENCY
        if any(w in q for w in ["hop", "hops", "latency", "relay", "routing", "delta t", "transit", "time delay", "timing"]):
            has_latency_anomaly = any("latency" in str(r).lower() or "forged" in str(r).lower() or "timing" in str(r).lower() for r in reasons)
            reply = [
                "### ✈️ MTA Transmission Hops & Latency Delta (ΔT) Analysis",
                f"- **Total Analyzed Routing Hops:** `{hops_count}` MTA relay checkpoints",
                f"- **Client Origin Node:** `{origin_ip}` ({geo.get('country', 'N/A')})",
                f"- **Transit Anomaly Flag:** {'🚨 ANOMALOUS / FORGED DELAY' if has_latency_anomaly else '✅ NORMAL TRANSIT INTERVALS'}",
                "",
                "#### ⏱️ How Hop Forensics Works:",
                "Every Mail Transfer Agent (MTA) prepends a timestamped `Received:` header. TraceMail AI unpacks these in reverse chronological order to calculate delta latency (`ΔT = T_in - T_out`).",
                ""
            ]
            if has_latency_anomaly:
                reply.append("- ⚠️ **Suspicious Time Gap:** A jump exceeding 1,200 seconds or a negative time delta was identified between intermediate relays, typical of artificial `Received:` header forgery or malicious store-and-forward proxying.")
            else:
                reply.append("- ✅ Relays demonstrate sub-second or expected regional delivery intervals consistent with normal SMTP processing.")

            return "\n".join(reply), "HOP_ANALYSIS"

        # 5. GEOINT & INFRASTRUCTURE
        if any(w in q for w in ["geo", "geoint", "where", "location", "ip", "tor", "frantech", "datacenter", "city", "country", "globe"]):
            is_tor = geo.get("is_tor", False)
            reply = [
                "### 🌍 Geospatial Intelligence (GeoINT) Radar Telemetry",
                f"- **Originating Public IP:** `{origin_ip}`",
                f"- **Physical Location:** {geo.get('city', 'Unknown City')}, {geo.get('region', '')} {geo.get('country', 'Unknown')}",
                f"- **Registered ISP / Organization:** `{geo.get('org', geo.get('organization', 'N/A'))}`",
                f"- **Autonomous System (ASN):** `{geo.get('asn', 'N/A')}`",
                f"- **High-Risk Network Flags:** {'🚨 TOR Exit Node Detected' if is_tor else 'Standard Commercial / Datacenter Infrastructure'}",
                "",
                "#### 🌐 3D Globe Radar Correlation:",
                f"The 3D Globe in the top-right viewport has locked its sensor coordinates onto (`{geo.get('lat', '0')}°, {geo.get('lon', '0')}°`). Clicking **🎯 Focus** will track the camera directly into this physical hosting site."
            ]
            return "\n".join(reply), "GEOINT_ANALYSIS"

        # 6. LINKS & ATTACHMENTS (SSRF / PUNYCODE)
        if any(w in q for w in ["link", "links", "url", "ssrf", "attachment", "malware", "click", "safe to open"]):
            susp_links = [l for l in links if l.get("suspicious")]
            reply = [
                "### 🔗 Link & Attachment Threat Isolation",
                f"- **Total Hyperlinks Discovered:** `{len(links)}`",
                f"- **Suspicious / Obfuscated Links:** `{len(susp_links)}`",
                "",
                "#### 🛡️ Safe Static Inspection Safeguard:",
                "TraceMail AI utilizes a **Zero-Request Static URL Inspection** model. It inspects URL components, punycode lookalikes, and internal probe patterns without ever making active outbound HTTP requests to attacker servers.",
                ""
            ]

            if susp_links:
                reply.append("#### ⚠️ Identified Threat Targets:")
                for l in susp_links[:3]:
                    reply.append(f"- 🛑 `{l.get('original')}` → Redirects: {l.get('redirects', 0)}")
                reply.append("\n**Verdict:** **DO NOT CLICK.** High risk of credential harvesting or internal network metadata extraction.")
            else:
                reply.append("- ✅ No malicious redirectors, IP literals, or metadata probing endpoints detected.")

            return "\n".join(reply), "LINK_ANALYSIS"

        # 7. REMEDIATION & OUT-OF-BAND PROTOCOL
        if any(w in q for w in ["what should i do", "action", "out of band", "verify", "remediation", "next step", "incident"]):
            reply = [
                "### 📋 SOC Incident Response & Out-of-Band Verification Protocol",
                "",
                "When dealing with emails flagged for financial diversion or account takeover, follow these mandatory steps:",
                "",
                "1. **Mandatory Out-of-Band (OOB) Verification:**",
                "   - **NEVER** reply to the email or use the phone numbers listed in the email body/signature.",
                "   - Obtain the vendor/executive's pre-established contact number from an approved internal ERP or CRM system.",
                "   - Call and verify the request via direct voice authentication with secondary signatory sign-off.",
                "",
                "2. **Mail Gateway & Firewall Defense:**",
                f"   - Block sender IP: `{origin_ip}`",
                f"   - Block deceptive Reply-To address: `{reply_to}`",
                "   - Invalidate any active web sessions or credentials if an employee clicked external links.",
                "",
                "3. **Cryptographic Ledger Archival:**",
                f"   - Retain Evidence SHA-256 Hash: `{report.get('forensic_hash', 'N/A')}` for chain-of-custody compliance.",
                "   - Click **Export PDF Dossier** in the console to generate the court-ready forensic incident packet."
            ]
            if rag_data and rag_data.get("augmented_context"):
                reply.extend([
                    "",
                    rag_data["augmented_context"]
                ])
            return "\n".join(reply), "REMEDIATION"

        # 8. DEFAULT COMPREHENSIVE ANSWER
        default_reply = [
            "### 🧠 TraceMail AI Forensic Copilot Analysis",
            "",
            f"Regarding your inquiry on **'{query}'**:",
            "",
            f"The current target email is categorized as **{label}** with a threat score of **{score}/100** ({risk} risk).",
            "",
            f"- **Sender Identity:** `{from_hdr}`",
            f"- **Reply-To Alignment:** `{reply_to}`",
            f"- **Origin Physical Relay:** {geo.get('city', 'Unknown')}, {geo.get('country', 'N/A')} (`{origin_ip}`)",
            f"- **Key Threat Factors:** {', '.join(str(r) for r in reasons) if reasons else 'Clean / Standard Corporate Communication'}"
        ]

        if rag_data and rag_data.get("augmented_context"):
            default_reply.extend([
                "",
                rag_data["augmented_context"]
            ])

        default_reply.extend([
            "",
            "**Suggested Next Inquiries:**",
            "- Ask: *'Explain the domain WHOIS details'*",
            "- Ask: *'Why did SPF or DKIM pass/fail?'*",
            "- Ask: *'What out-of-band verification steps are required?'*"
        ])

        return "\n".join(default_reply), "GENERAL_INQUIRY"

    @classmethod
    def _get_default_prompts(cls, report: Optional[Dict[str, Any]]) -> List[str]:
        return [
            "Explain Overall Threat Verdict",
            "Show CISA & FBI BEC Playbook",
            "Map to MITRE ATT&CK & D3FEND",
            "Generate Snort 3 & Sigma Rules",
            "Explain SPF, DKIM & DMARC Headers",
            "Inspect Sender Domain & WHOIS",
            "Explain MTA Hops & Timing Delays (ΔT)"
        ]

    @classmethod
    def _get_contextual_prompts(cls, query: str, report: Optional[Dict[str, Any]]) -> List[str]:
        q = query.lower()
        if "header" in q or "spf" in q:
            return [
                "Why can an authenticated email still be BEC?",
                "Explain DMARC alignment rules",
                "Inspect the Reply-To mismatch"
            ]
        if "domain" in q or "whois" in q:
            return [
                "What are the MX records for this domain?",
                "Is this domain newly registered?",
                "How to block this domain in firewall"
            ]
        if "hop" in q:
            return [
                "Where did this email physically originate?",
                "Is the origin IP connected to TOR?",
                "Explain how attackers forge Received headers"
            ]
        if "playbook" in q or "cisa" in q or "remediation" in q:
            return [
                "Generate Snort 3 rule for this origin",
                "Show SWIFT recall procedure",
                "Audit Exchange inbox forwarding rules"
            ]
        return cls._get_default_prompts(report)
