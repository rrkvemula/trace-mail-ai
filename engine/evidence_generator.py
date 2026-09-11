"""
Forensic analysis report generator.
Produces a review aid with provenance and limitation notices.
"""

import os
import uuid
from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from xml.sax.saxutils import escape

class EvidenceGenerator:
    """Creates a standardized forensic PDF report with cryptographic chain of custody."""

    @classmethod
    def generate_pdf(cls, analysis_data: dict, output_path: str) -> str:
        safe = lambda value: escape(str(value if value is not None else ""))
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=36, leftMargin=36,
            topMargin=36, bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Forensic Styles
        title_style = ParagraphStyle(
            'ForensicTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=16,
            textColor=colors.HexColor('#0B1F3A'),
            alignment=1, # Center
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'ForensicSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.HexColor('#008080'),
            alignment=1,
            spaceAfter=12
        )
        heading_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=12,
            textColor=colors.HexColor('#0B1F3A'),
            spaceBefore=8,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'ForensicBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#1E293B'),
            leading=12
        )
        code_style = ParagraphStyle(
            'ForensicCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            textColor=colors.HexColor('#0F172A'),
            leading=10
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("TRACE-MAIL AI • FORENSIC ANALYSIS REPORT", title_style))
        story.append(Paragraph("TECHNICAL REVIEW AID • NOT AN AUTOMATIC CERTIFICATE OF ADMISSIBILITY OR ATTRIBUTION", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0B1F3A'), spaceAfter=10))

        # 2. Case Identification & Evidence Hash
        case_id = analysis_data.get("analysis_id") or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        hash_val = analysis_data.get("forensic_hash", "UNKNOWN")
        threat_verdict = analysis_data.get("threat_analysis", {}).get("verdict", "N/A")
        threat_score = analysis_data.get("threat_analysis", {}).get("threat_score", 0.0)
        ml_data = analysis_data.get("ml_analysis", {})
        ledger = analysis_data.get("ledger_receipt", {})

        meta_table_data = [
            [Paragraph("<b>Case Reference ID:</b>", body_style), Paragraph(safe(case_id), code_style),
             Paragraph("<b>Examination Date:</b>", body_style), Paragraph(safe(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')), body_style)],
            [Paragraph("<b>Exact submitted-byte SHA-256:</b>", body_style), Paragraph(safe(hash_val), code_style),
             Paragraph("<b>Threat Assessment:</b>", body_style), Paragraph(f"<b>{threat_score}/100</b> ({safe(threat_verdict)})", body_style)],
            [Paragraph("<b>Ledger record hash:</b>", body_style), Paragraph(safe(ledger.get("record_hash", "N/A")), code_style),
             Paragraph("<b>ML baseline:</b>", body_style), Paragraph(f"{float(ml_data.get('phishing_probability', 0.5)) * 100:.1f}% ({safe(ml_data.get('label', 'UNCERTAIN'))})", body_style)]
        ]
        t_meta = Table(meta_table_data, colWidths=[115, 195, 90, 120])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_meta)
        story.append(Spacer(1, 10))

        # 3. Message Envelope Details
        story.append(Paragraph("1. Message Envelope & Authentication Posture", heading_style))
        headers = analysis_data.get("headers", {})
        auth = analysis_data.get("authentication", {})

        env_data = [
            [Paragraph("<b>From:</b>", body_style), Paragraph(safe(headers.get("from", "N/A")), body_style)],
            [Paragraph("<b>To:</b>", body_style), Paragraph(safe(headers.get("to", "N/A")), body_style)],
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(safe(headers.get("subject", "N/A")), body_style)],
            [Paragraph("<b>Sender Date:</b>", body_style), Paragraph(safe(headers.get("date", "N/A")), body_style)],
            [Paragraph("<b>Reported SPF:</b>", body_style), Paragraph(safe(f"{auth.get('spf', {}).get('status', 'NONE')} ({auth.get('spf', {}).get('details', '')})"), body_style)],
            [Paragraph("<b>Reported DKIM:</b>", body_style), Paragraph(safe(f"{auth.get('dkim', {}).get('status', 'NONE')} ({auth.get('dkim', {}).get('details', '')})"), body_style)],
            [Paragraph("<b>Reported DMARC:</b>", body_style), Paragraph(safe(f"{auth.get('dmarc', {}).get('status', 'NONE')} ({auth.get('dmarc', {}).get('details', '')})"), body_style)]
        ]
        t_env = Table(env_data, colWidths=[115, 405])
        t_env.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F8FAFC')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_env)
        story.append(Spacer(1, 10))

        # 4. Hop-by-Hop Transmission Audit Table
        story.append(Paragraph("2. Chronological Relay Hop & Latency (ΔT) Audit", heading_style))
        hops = analysis_data.get("hops_analysis", {}).get("analyzed_hops", [])

        hop_table_data = [["Hop", "Relaying IP", "From MTA -> By MTA", "Geolocation", "Latency (ΔT)", "Integrity"]]
        for h in hops:
            ip_val = h.get("ip") or "Internal"
            geo_str = f"{h.get('geo', {}).get('city', '')}, {h.get('geo', {}).get('country_code', '')}"
            delta_val = f"{h.get('delta_seconds', 0.0):.1f}s" if h.get('delta_seconds') is not None else "--"
            status_str = "TIMESTAMP ANOMALY" if h.get("anomaly") else "OBSERVED"
            
            mta_str = f"{h.get('from_mta', '')[:18]} -> {h.get('by_mta', '')[:18]}"
            
            hop_table_data.append([
                str(h.get("hop_number", "")),
                ip_val,
                mta_str,
                geo_str,
                delta_val,
                status_str
            ])

        if len(hop_table_data) > 1:
            t_hops = Table(hop_table_data, colWidths=[28, 82, 165, 105, 60, 80])
            t_hops.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0B1F3A')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('ALIGN', (2, 1), (2, -1), 'LEFT'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(t_hops)
        else:
            story.append(Paragraph("No intermediate hops recorded.", body_style))

        story.append(Spacer(1, 10))

        # 5. Indicators of Compromise (IOCs) & Threat Factors
        story.append(Paragraph("3. Forensic Indicators of Compromise (IOCs) & Findings", heading_style))
        factors = analysis_data.get("threat_analysis", {}).get("explainability_factors", [])
        if factors:
            for f in factors:
                bullet_p = Paragraph(f"• <b>[{safe(f.get('category'))}] ({safe(f.get('impact'))}):</b> {safe(f.get('detail'))}", body_style)
                story.append(bullet_p)
                story.append(Spacer(1, 2))
        else:
            story.append(Paragraph("No malicious indicators or anomalies identified.", body_style))

        story.append(Spacer(1, 14))

        # 6. Evidence integrity and limitations
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0B1F3A'), spaceAfter=8))
        story.append(Paragraph("4. Evidence Integrity, Provenance & Limitations", heading_style))
        cert_text = (
            "The SHA-256 value above was calculated from the exact bytes submitted to this analysis. Authentication statuses "
            "are interpreted from headers contained in the message and are not independently replayed by this prototype. "
            "GeoIP describes approximate network infrastructure, not a person's identity or physical location. Relay headers "
            "may contain untrusted claims. This report supports analyst review and does not by itself establish legal admissibility, "
            "authorship, or attribution. An authorized investigator must preserve the source evidence and document custody."
        )
        story.append(Paragraph(cert_text, ParagraphStyle('CertBody', parent=body_style, fontSize=8, leading=11)))
        story.append(Spacer(1, 20))

        # Sign-off box
        sign_data = [
            [Paragraph("<b>Analysis System:</b> TRACE-MAIL AI (SIH Prototype)", body_style),
             Paragraph("<b>Analyst Review:</b> ___________________________", body_style)],
            [Paragraph("<b>Institution:</b> Sir C.R. Reddy College of Engineering (Autonomous)", body_style),
             Paragraph("<b>Official Seal / Date:</b> ___________________________", body_style)]
        ]
        t_sign = Table(sign_data, colWidths=[260, 260])
        t_sign.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_sign)

        # Build Document
        doc.build(story)
        return output_path
