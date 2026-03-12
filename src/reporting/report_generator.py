"""Forensic report generator implementation.

Provides `ForensicReportGenerator` for creating detailed forensic reports
in JSON and PDF formats.
"""
import json
import os
import html
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

from ..utils.exiftool_formatter import ExifToolStyleFormatter


class ForensicReportGenerator:
    """Generates forensic reports in multiple formats."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    def generate(self, title: str | None = None, analysis_results: Dict[str, Any] | None = None, 
                 output_format: str = 'json', output_path: str | None = None, 
                 output_dir: str | None = None, formats: List[str] | None = None) -> Dict[str, Any]:
        """
        Generate forensic reports.
        
        Args:
            title: Report title.
            analysis_results: Dictionary containing analysis data.
            output_format: Primary format (deprecated, use formats).
            output_path: Specific output path (optional).
            output_dir: Directory to save reports.
            formats: List of formats to generate ['json', 'pdf'].
            
        Returns:
            Dictionary of generated report paths.
        """
        if not analysis_results:
            return {'error': 'No analysis results provided'}

        # Determine output location
        if output_dir:
            out_dir_path = Path(output_dir)
        elif output_path:
            out_dir_path = Path(output_path).parent
        else:
            out_dir_path = Path('results/reports')
        
        out_dir_path.mkdir(parents=True, exist_ok=True)
        
        # Base filename
        image_path = analysis_results.get('evidence_integrity', {}).get('file_path') or \
                     analysis_results.get('image_path')
        
        if image_path:
            base_name = Path(image_path).stem
        else:
            base_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_paths = {}
        
        target_formats = formats or [output_format]
        if 'both' in target_formats or 'all' in target_formats:
            target_formats = ['json', 'pdf', 'html', 'txt']

        # Generate JSON
        if 'json' in target_formats:
            json_path = out_dir_path / f"{base_name}_{timestamp}.json"
            self._write_json(analysis_results, json_path)
            report_paths['json'] = str(json_path)

        # Generate HTML
        if 'html' in target_formats:
            html_path = out_dir_path / f"{base_name}_{timestamp}.html"
            self._write_html(title or "Forensic Analysis Report", analysis_results, html_path)
            report_paths['html'] = str(html_path)

        # Generate PDF
        if 'pdf' in target_formats:
            pdf_path = out_dir_path / f"{base_name}_{timestamp}.pdf"
            self._write_pdf(title or "Forensic Analysis Report", analysis_results, pdf_path)
            report_paths['pdf'] = str(pdf_path)

        # Generate Text (ExifTool Style)
        if 'txt' in target_formats or 'text' in target_formats:
            txt_path = out_dir_path / f"{base_name}_{timestamp}.txt"
            self._write_text(analysis_results, txt_path)
            report_paths['txt'] = str(txt_path)

        return report_paths

    def _write_json(self, data: Dict[str, Any], path: Path) -> None:
        """Write data to JSON file."""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, default=str)

    def _render_kv_table_html(self, payload: Dict[str, Any]) -> str:
        """Render a dictionary as a simple two-column HTML table."""
        if not isinstance(payload, dict) or not payload:
            return "<p>No data available.</p>"

        rows = []
        for key, value in payload.items():
            if isinstance(value, dict):
                if key in {'features', 'decision_trace'} and value:
                    nested_items = "".join(
                        [f"<li><strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}</li>" for k, v in value.items()]
                    )
                    rendered = f"<ul style='margin: 0; padding-left: 20px;'>{nested_items}</ul>"
                elif len(value) <= 6:
                    nested_items = "".join(
                        [f"<li><strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}</li>" for k, v in value.items()]
                    )
                    rendered = f"<ul style='margin: 0; padding-left: 20px;'>{nested_items}</ul>"
                else:
                    rendered = f"{len(value)} fields"
            elif isinstance(value, list):
                if key == 'flags' and all(not isinstance(v, (dict, list)) for v in value):
                    if value:
                        rendered_items = "".join([f"<li>{html.escape(str(v))}</li>" for v in value])
                        rendered = f"<ul style='margin: 0; padding-left: 20px;'>{rendered_items}</ul>"
                    else:
                        rendered = "No flags"
                elif all(not isinstance(v, (dict, list)) for v in value) and len(value) <= 5:
                    rendered = ", ".join([html.escape(str(v)) for v in value]) if value else "0 items"
                else:
                    rendered = f"{len(value)} items"
            else:
                rendered = html.escape(str(value))
            rows.append(f"<tr><td>{html.escape(str(key))}</td><td>{rendered}</td></tr>")

        return f"""
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            {''.join(rows)}
        </table>
        """

    def _render_module_outputs_html(self, module_outputs: Dict[str, Any]) -> str:
        """Render explainability module outputs as readable cards."""
        if not isinstance(module_outputs, dict) or not module_outputs:
            return "<p>No module outputs available.</p>"

        cards = []
        for module_name, module_payload in module_outputs.items():
            if isinstance(module_payload, dict):
                summary_table = self._render_kv_table_html(module_payload)
            else:
                summary_table = self._render_kv_table_html({'value': module_payload})

            cards.append(f"""
            <div class="finding" style="border: 1px solid #d1d5da; border-radius: 8px; padding: 14px; margin-bottom: 12px; background: #fff;">
                <h3 style="margin: 0 0 8px 0; color: #2c3e50;">{html.escape(str(module_name).replace('_', ' ').title())}</h3>
                {summary_table}
            </div>
            """)

        return "".join(cards)

    def _render_forensic_reasoning_html(self, reasoning: Dict[str, Any]) -> str:
        """Render explain_forensic_reasoning as structured HTML sections."""
        if not isinstance(reasoning, dict) or not reasoning:
            return ""

        plain = reasoning.get('0_plain_language_summary', {})
        risk = reasoning.get('1_multi_domain_risk_assessment', {})
        severities = reasoning.get('2_evidence_severity_classification', [])
        conflict = reasoning.get('3_model_conflict_analysis', {})
        calibration = reasoning.get('4_bayesian_calibration_commentary', {})
        unified = reasoning.get('5_unified_interpretation_improved_classification', 'INCONCLUSIVE')
        confidence = reasoning.get('6_forensic_confidence_index', {})
        narrative = reasoning.get('7_narrative_forensic_summary', '')
        deterministic = conflict.get('deterministic_aggregation', {})
        bayesian = conflict.get('bayesian_predictive_model', {})

        severity_rows = ""
        for item in severities:
            severity_rows += (
                f"<tr><td>{html.escape(str(item.get('indicator', 'N/A')))}</td>"
                f"<td>{html.escape(str(item.get('severity', 'LOW')))}</td>"
                f"<td>{html.escape(str(item.get('reason', '')))}</td></tr>"
            )
        if not severity_rows:
            severity_rows = "<tr><td colspan='3'>No flagged indicators.</td></tr>"

        dominance = conflict.get('dominance_factors', [])
        dominance_html = "".join([f"<li>{html.escape(str(x))}</li>" for x in dominance]) or "<li>No dominance factors recorded.</li>"
        supports_html = "".join([f"<li>{html.escape(str(x))}</li>" for x in plain.get('what_supports_this', [])]) or "<li>No additional support points.</li>"
        limits_html = "".join([f"<li>{html.escape(str(x))}</li>" for x in plain.get('what_this_does_not_prove', [])]) or "<li>No limitations listed.</li>"

        return f"""
        <h2>Explain Output (Forensic Reasoning)</h2>
        <div class="metadata-box">
            <h3>0. Plain-Language Summary</h3>
            <p><strong>Simple Verdict:</strong> {html.escape(str(plain.get('simple_verdict', 'N/A')))}</p>
            <p><strong>Confidence:</strong> {html.escape(str(plain.get('plain_confidence', 'N/A')))}</p>
            <p><strong>What supports this:</strong></p>
            <ul>{supports_html}</ul>
            <p><strong>What this does not prove:</strong></p>
            <ul>{limits_html}</ul>
            <p>{html.escape(str(plain.get('recommended_reading', '')))}</p>

            <h3>1. Multi-Domain Risk Assessment</h3>
            {self._render_kv_table_html(risk)}

            <h3>2. Evidence Severity Classification</h3>
            <table>
                <tr><th>Indicator</th><th>Severity</th><th>Reason</th></tr>
                {severity_rows}
            </table>

            <h3>3. Model Conflict Analysis</h3>
            <p><strong>Conflict Detected:</strong> {conflict.get('conflict_detected', False)}</p>
            <p><strong>Deterministic Aggregation:</strong></p>
            {self._render_kv_table_html(deterministic)}
            <p><strong>Bayesian Predictive Model:</strong></p>
            {self._render_kv_table_html(bayesian)}
            <ul>{dominance_html}</ul>

            <h3>4. Bayesian Calibration Commentary</h3>
            <p><strong>Likelihood Overweighted:</strong> {calibration.get('likelihood_overweighted', False)}</p>
            <p>{html.escape(str(calibration.get('commentary', '')))}</p>

            <h3>5. Unified Interpretation (Improved Classification)</h3>
            <p><strong>{html.escape(str(unified))}</strong></p>

            <h3>6. Forensic Confidence Index</h3>
            <p><strong>Level:</strong> {html.escape(str(confidence.get('level', 'LOW')))}</p>
            <p>{html.escape(str(confidence.get('basis', '')))}</p>

            <h3>7. Narrative Forensic Summary</h3>
            <p>{html.escape(str(narrative))}</p>
        </div>
        """

    def _render_modification_history_html(self, history: Dict[str, Any]) -> str:
        """Render modification-history summary for HTML reports."""
        if not isinstance(history, dict) or not history:
            return "<p>No modification history available.</p>"

        event_rows = []
        for event in history.get('events', []):
            event_rows.append(
                f"<tr><td>{html.escape(str(event.get('event', 'N/A')))}</td>"
                f"<td>{html.escape(str(event.get('timestamp', 'N/A')))}</td>"
                f"<td>{html.escape(str(event.get('source', 'N/A')))}</td>"
                f"<td>{html.escape(str(event.get('confidence', 'N/A')))}</td>"
                f"<td>{html.escape(str(event.get('details', '')))}</td></tr>"
            )

        if not event_rows:
            event_rows.append("<tr><td colspan='5'>No history events detected.</td></tr>")

        software_html = "".join([f"<li>{html.escape(str(item))}</li>" for item in history.get('software_detected', [])]) or "<li>No software markers detected.</li>"
        xmp_html = "".join([f"<li>{html.escape(str(item))}</li>" for item in history.get('xmp_history_entries', [])]) or "<li>No XMP history entries detected.</li>"

        return f"""
        <div class="metadata-box">
            <p><strong>Status:</strong> {html.escape(str(history.get('status', 'unknown')))}</p>
            <p><strong>Confidence:</strong> {html.escape(str(history.get('confidence', 'low')))}</p>
            <p><strong>Likely Modified:</strong> {html.escape(str(history.get('likely_modified', False)))}</p>
            <p><strong>Summary:</strong> {html.escape(str(history.get('summary', 'No summary available.')))}</p>
            <p><strong>Original Capture Time:</strong> {html.escape(str(history.get('original_capture_time', 'N/A')))}</p>
            <p><strong>Digitized Time:</strong> {html.escape(str(history.get('digitized_time', 'N/A')))}</p>
            <p><strong>File Modified Time:</strong> {html.escape(str(history.get('file_modified_time', 'N/A')))}</p>
            <p><strong>Software Detected:</strong></p>
            <ul>{software_html}</ul>
            <p><strong>XMP History Entries:</strong></p>
            <ul>{xmp_html}</ul>
            <table>
                <tr><th>Event</th><th>Timestamp</th><th>Source</th><th>Confidence</th><th>Details</th></tr>
                {''.join(event_rows)}
            </table>
        </div>
        """

    def _summarize_for_pdf(self, value: Any) -> str:
        """Create concise, PDF-friendly summaries for complex values."""
        if isinstance(value, dict):
            return f"{len(value)} fields"
        if isinstance(value, list):
            if not value:
                return "0 items"
            if all(not isinstance(v, (dict, list)) for v in value):
                preview = ", ".join(str(v) for v in value[:3])
                suffix = " ..." if len(value) > 3 else ""
                return f"{len(value)} items: {preview}{suffix}"
            return f"{len(value)} items"
        return str(value)

    def _compact_pdf_cell(self, value: Any, max_chars: int = 400) -> str:
        """Normalize and truncate table cell text to keep rows printable in PDF."""
        if isinstance(value, (dict, list)):
            text = json.dumps(value, default=str)
        else:
            text = str(value)

        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = " | ".join(part.strip() for part in text.split("\n") if part.strip())

        if len(text) > max_chars:
            text = f"{text[:max_chars]} ... [truncated]"

        # Insert break opportunities in long unbroken tokens.
        return re.sub(r"(\S{60})", r"\1 ", text)

    def _write_html(self, title: str, data: Dict[str, Any], path: Path) -> None:
        """Generate a professional HTML forensic report."""
        include_raw = bool(data.get('include_raw', False))
        explain_mode = data.get('ai_mode') == 'explain' and not include_raw
        risk = data.get('risk_assessment', {})
        interpretation = risk.get('unified_interpretation', 'UNKNOWN')
        explainability = data.get('explainability_breakdown', {})
        explain_reasoning = data.get('explain_forensic_reasoning', {})
        modification_history = data.get('modification_history', {})
        assist = data.get('assist_suggestions', {})
        decision_trace_html = self._render_kv_table_html(explainability.get('decision_trace', {}))
        module_outputs_html = self._render_module_outputs_html(explainability.get('module_outputs', {}))
        explain_reasoning_html = self._render_forensic_reasoning_html(explain_reasoning)
        modification_history_html = self._render_modification_history_html(modification_history)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{title}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; color: #333; line-height: 1.6; background-color: #fcfcfc; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #34495e; padding-bottom: 10px; }}
                h2 {{ color: #e67e22; margin-top: 30px; border-left: 5px solid #e67e22; padding-left: 15px; }}
                .summary {{ background: #f9f9f9; padding: 20px; border-radius: 8px; border-left: 5px solid #3498db; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
                .critical {{ color: #c0392b; font-weight: bold; }}
                .finding {{ padding: 10px; margin: 5px 0; border-bottom: 1px solid #eee; }}
                
                /* Metadata Box Styling */
                .metadata-box {{ 
                    background: white; 
                    border: 1px solid #d1d5da; 
                    border-radius: 8px; 
                    padding: 20px; 
                    margin: 20px 0; 
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1); 
                    max-height: 500px; 
                    overflow-y: auto; 
                }}
                
                .raw-box {{
                    background: #1e1e1e;
                    color: #d4d4d4;
                    padding: 20px;
                    border-radius: 8px;
                    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                    font-size: 0.9em;
                    white-space: pre-wrap;
                    overflow-x: auto;
                    border-left: 5px solid #007acc;
                }}

                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ padding: 12px; text-align: left; border: 1px solid #eee; }}
                th {{ background-color: #f8f9fa; color: #2c3e50; font-weight: 600; }}
                tr:nth-child(even) {{ background-color: #fafafa; }}
                tr:hover {{ background-color: #f1f1f1; }}
            </style>
        </head>
        <body>
            <h1>{title}</h1>
            <div class="summary">
                <p><strong>Case Evidence:</strong> {data.get('image_path', 'N/A')}</p>
                <p><strong>Forensic Interpretation:</strong> <span class="critical">{interpretation.replace('_', ' ')}</span></p>
                <p><strong>Risk Score:</strong> {risk.get('risk_score', 0):.1f}/100 ({risk.get('level', 'LOW')})</p>
                <p><strong>Analysis Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <h2>Unified Forensic Conclusion</h2>
            <div class="metadata-box" style="background: #fffdf9; border-left: 5px solid #e67e22;">
                <p>{risk.get('findings_summary', 'No summary available.')}</p>
            </div>

            <h2>Forensic Justifications (XAI)</h2>
            {"".join([f'''
                <div class="finding" style="border: 1px solid #34495e; padding: 20px; margin-bottom: 20px; border-radius: 8px; background: white;">
                    <h3 style="margin-top: 0; color: {"#c0392b" if e.get("severity") == "CRITICAL" else "#d35400" if e.get("severity") == "HIGH" else "#2c3e50"};">
                        [{e.get("confidence")}] {e.get("title")}
                    </h3>
                    <p><strong>Observation:</strong> {e.get("observation")}</p>
                    <p><strong>Metadata Triggers:</strong> <code>{json.dumps(e.get("triggers", {}))}</code></p>
                    <p><strong>Forensic Logic:</strong> {e.get("logic")}</p>
                    <p><strong>Expert Significance:</strong> {e.get("significance")}</p>
                    <div style="background: #ecf0f1; padding: 10px; border-radius: 4px; margin-top: 10px;">
                        <strong>Potential Interpretations:</strong>
                        <ul style="margin: 5px 0;">
                            <li><em>Legitimate:</em> {e.get("causes", {}).get("legitimate")}</li>
                            <li><em>Malicious:</em> {e.get("causes", {}).get("malicious")}</li>
                        </ul>
                    </div>
                </div>
            ''' for e in data.get('explanations', [])])}

            {explain_reasoning_html if explain_reasoning else ""}

            <h2>Modification History</h2>
            {modification_history_html}

            {f'''
            <h2>Assist Mode (Analyst Augmentation)</h2>
            <div class="metadata-box">
                <p><strong>Suggested Structural Finding:</strong> {html.escape(str(assist.get('suggested_structural_finding', 'N/A')))}</p>
                <p><strong>Suggested Interpretation:</strong> {html.escape(str(assist.get('suggested_interpretation', 'N/A')))}</p>
                <p><strong>Suggested Risk Level:</strong> {html.escape(str(assist.get('suggested_risk_level', 'N/A')))}</p>
                <p><strong>Suggested Follow-up:</strong></p>
                <ul>{"".join([f"<li>{html.escape(str(step))}</li>" for step in assist.get('suggested_follow_up', [])])}</ul>
                <p><strong>Final Decision:</strong> {html.escape(str(assist.get('final_decision', 'Pending Analyst Confirmation')))}</p>
            </div>
            ''' if assist else ""}

            {("" if explain_mode else f'''
            <h2>Investigative Raw Metadata</h2>
            <div class="raw-box">
{ExifToolStyleFormatter.format(data.get('metadata', {}))}
            </div>

            <h2>File System Metadata</h2>
            <div class="metadata-box">
                <table>
                    <tr><th>Attribute</th><th>Value</th></tr>
                    {"".join([f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data.get('metadata', {}).get('file_info', {}).items() if not k.islower()]) if isinstance(data.get('metadata', {}).get('file_info'), dict) else "<tr><td colspan='2'>No file information available.</td></tr>"}
                </table>
            </div>

            {f'<h2>ICC Profile</h2><div class="metadata-box"><table><tr><th>Attribute</th><th>Value</th></tr>{"".join([f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data.get("metadata", {}).get("icc_profile", {}).items()]) if isinstance(data.get("metadata", {}).get("icc_profile"), dict) else "<tr><td colspan=\'2\'>No ICC profile detected.</td></tr>"}</table></div>' if data.get("metadata", {}).get("icc_profile") else ""}

            <h2>Composite Forensic Tags</h2>
            <div class="metadata-box">
                <table>
                    <tr><th>Tag</th><th>Value</th></tr>
                    {"".join([f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data.get('metadata', {}).get('composite', {}).items()]) if isinstance(data.get('metadata', {}).get('composite'), dict) else "<tr><td colspan='2'>No composite tags generated.</td></tr>"}
                </table>
            </div>
            ''')}

            <footer style="margin-top: 50px; font-size: 0.8em; color: #7f8c8d;">
                Generated by MetaForensicAI Enterprise v1.0.0 | Forensic Integrity Guaranteed
            </footer>
        </body>
        </html>
        """
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _write_pdf(self, title: str, data: Dict[str, Any], path: Path) -> None:
        """Write data to PDF file using ReportLab."""
        include_raw = bool(data.get('include_raw', False))
        explain_mode = data.get('ai_mode') == 'explain' and not include_raw
        doc = SimpleDocTemplate(str(path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph(title, styles['Title']))
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        
        risk = data.get('risk_assessment', {})
        risk_score = risk.get('score', data.get('risk_score', 0))
        level = risk.get('level', 'LOW')
        authentic = data.get('authentic', False)
        
        summary_text = f"""
        <b>Authenticity:</b> {'Authentic' if authentic else 'Suspicious'}<br/>
        <b>Risk Score:</b> {risk_score:.1f}/100 ({level})<br/>
        <b>Primary Origin:</b> {data.get('origin_detection', {}).get('primary_origin', 'Unknown')}<br/>
        <b>Analysis Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 12))

        # 1. Forensic Domain Context (Point 8)
        domains = data.get('domains', {})
        if domains:
            story.append(Paragraph("Forensic Domain Expertise", styles['Heading2']))
            fmt = domains.get('image_format', {})
            mfr = domains.get('manufacturer', {})
            story.append(Paragraph(f"<b>Format Domain:</b> {fmt.get('label')} ({fmt.get('expertise', {}).get('forensics')})", styles['Normal']))
            story.append(Paragraph(f"<b>Manufacturer Domain:</b> {mfr.get('label')} ({mfr.get('expertise', {}).get('notes')})", styles['Normal']))
            story.append(Spacer(1, 12))

        # 2. Evidence Correlation & Conclusion (Point 9)
        risk = data.get('risk_assessment', {})
        interpretation = risk.get('unified_interpretation', 'UNKNOWN')
        story.append(Paragraph("Unified Forensic Conclusion", styles['Heading2']))
        story.append(Paragraph(f"<b>Interpretation:</b> {interpretation.replace('_', ' ')}", styles['Normal']))
        story.append(Paragraph(f"<b>Risk Level:</b> {risk.get('level', 'UNKNOWN')} ({risk.get('risk_score', 0):.1f}/100)", styles['Normal']))
        story.append(Spacer(1, 12))

        # 3. XAI Explanations (Point 10)
        explanations = data.get('explanations', [])
        if explanations:
            story.append(Paragraph("Forensic Justifications (XAI)", styles['Heading2']))
            for exp in explanations:
                severity_color = 'red' if exp.get('severity') in ['HIGH', 'CRITICAL'] else 'orange' if exp.get('severity') == 'MEDIUM' else 'black'
                
                # Narrative Card Style
                story.append(Paragraph(f"<b>[{exp.get('confidence')}] {exp.get('title')}</b>", styles['Heading3']))
                story.append(Paragraph(f"<b>Observation:</b> {exp.get('observation')}", styles['Normal']))
                story.append(Paragraph(f"<b>Metadata Triggers:</b> {json.dumps(exp.get('triggers', {}))}", styles['Italic']))
                story.append(Paragraph(f"<b>Forensic Logic:</b> {exp.get('logic')}", styles['Normal']))
                story.append(Paragraph(f"<b>Expert Significance:</b> {exp.get('significance')}", styles['Normal']))
                
                causes = exp.get('causes', {})
                story.append(Paragraph(f"<b><i>- Legitimate Cause:</i></b> {causes.get('legitimate')}", styles['Normal']))
                story.append(Paragraph(f"<b><i>- Malicious Cause:</i></b> {causes.get('malicious')}", styles['Normal']))
                story.append(Spacer(1, 10))
            story.append(Spacer(1, 12))

        modification_history = data.get('modification_history', {})
        if modification_history:
            story.append(Paragraph("Modification History", styles['Heading2']))
            story.append(Paragraph(f"Status: {modification_history.get('status', 'unknown')}", styles['Normal']))
            story.append(Paragraph(f"Confidence: {modification_history.get('confidence', 'low')}", styles['Normal']))
            story.append(Paragraph(f"Likely Modified: {modification_history.get('likely_modified', False)}", styles['Normal']))
            story.append(Paragraph(f"Summary: {modification_history.get('summary', 'No summary available.')}", styles['Normal']))
            story.append(Paragraph(f"Original Capture Time: {modification_history.get('original_capture_time', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Digitized Time: {modification_history.get('digitized_time', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"File Modified Time: {modification_history.get('file_modified_time', 'N/A')}", styles['Normal']))
            for item in modification_history.get('software_detected', []):
                story.append(Paragraph(f"Software: {item}", styles['Normal']))
            for item in modification_history.get('xmp_history_entries', []):
                story.append(Paragraph(f"XMP History: {item}", styles['Normal']))
            for event in modification_history.get('events', []):
                story.append(Paragraph(
                    f"- {event.get('event', 'N/A')} | {event.get('timestamp', 'N/A')} | {event.get('source', 'N/A')} | {event.get('confidence', 'N/A')} | {event.get('details', '')}",
                    styles['Normal']
                ))
            story.append(Spacer(1, 12))

        # 3.5 Explainability Breakdown (Explain Mode)
        explainability = data.get('explainability_breakdown', {})
        if explainability and not explain_mode:
            story.append(Paragraph("Explainability Breakdown", styles['Heading2']))
            story.append(Paragraph(f"<b>Pipeline Mode:</b> {explainability.get('pipeline_mode', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"<b>Explanation Count:</b> {explainability.get('explanation_count', 0)}", styles['Normal']))

            decision_trace = explainability.get('decision_trace', {})
            if decision_trace:
                story.append(Paragraph("<b>Decision Trace:</b>", styles['Heading3']))
                for key, value in decision_trace.items():
                    story.append(Paragraph(f"{key}: {self._summarize_for_pdf(value)}", styles['Normal']))

            module_outputs = explainability.get('module_outputs', {})
            if module_outputs:
                story.append(Paragraph("<b>Module Outputs:</b>", styles['Heading3']))
                for module_name, module_payload in module_outputs.items():
                    story.append(Paragraph(f"<b>{module_name}:</b>", styles['Normal']))
                    if isinstance(module_payload, dict):
                        for key, value in module_payload.items():
                            story.append(Paragraph(f"• {key}: {self._summarize_for_pdf(value)}", styles['Normal']))
                    else:
                        story.append(Paragraph(f"• {self._summarize_for_pdf(module_payload)}", styles['Normal']))
                    story.append(Spacer(1, 6))

            story.append(Spacer(1, 12))

        # 3.6 Structured Explain Reasoning (Explain Mode)
        explain_reasoning = data.get('explain_forensic_reasoning', {})
        if explain_reasoning:
            story.append(Paragraph("Explain Output (Forensic Reasoning)", styles['Heading2']))

            plain = explain_reasoning.get('0_plain_language_summary', {})
            if plain:
                story.append(Paragraph("0. Plain-Language Summary", styles['Heading3']))
                story.append(Paragraph(f"Simple Verdict: {plain.get('simple_verdict', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"Confidence: {plain.get('plain_confidence', 'N/A')}", styles['Normal']))
                story.append(Paragraph("What supports this:", styles['Normal']))
                for item in plain.get('what_supports_this', []):
                    story.append(Paragraph(f"• {item}", styles['Normal']))
                story.append(Paragraph("What this does not prove:", styles['Normal']))
                for item in plain.get('what_this_does_not_prove', []):
                    story.append(Paragraph(f"• {item}", styles['Normal']))
                story.append(Paragraph(str(plain.get('recommended_reading', '')), styles['Normal']))
                story.append(Spacer(1, 8))

            risk = explain_reasoning.get('1_multi_domain_risk_assessment', {})
            story.append(Paragraph("1. Multi-Domain Risk Assessment", styles['Heading3']))
            for key, value in risk.items():
                story.append(Paragraph(f"{key}: {self._summarize_for_pdf(value)}", styles['Normal']))

            story.append(Paragraph("2. Evidence Severity Classification", styles['Heading3']))
            for item in explain_reasoning.get('2_evidence_severity_classification', []):
                story.append(Paragraph(
                    f"• {item.get('indicator')}: {item.get('severity')} - {item.get('reason')}",
                    styles['Normal']
                ))

            conflict = explain_reasoning.get('3_model_conflict_analysis', {})
            deterministic = conflict.get('deterministic_aggregation', {})
            bayesian = conflict.get('bayesian_predictive_model', {})
            story.append(Paragraph("3. Model Conflict Analysis", styles['Heading3']))
            story.append(Paragraph(f"Conflict Detected: {conflict.get('conflict_detected', False)}", styles['Normal']))
            story.append(Paragraph("Deterministic Aggregation:", styles['Normal']))
            story.append(Paragraph(f"• risk_score: {deterministic.get('risk_score')}", styles['Normal']))
            story.append(Paragraph(f"• risk_level: {deterministic.get('risk_level')}", styles['Normal']))
            story.append(Paragraph(f"• interpretation: {deterministic.get('interpretation')}", styles['Normal']))
            story.append(Paragraph("Bayesian Predictive Model:", styles['Normal']))
            story.append(Paragraph(f"• risk_score: {bayesian.get('risk_score')}", styles['Normal']))
            story.append(Paragraph(f"• risk_level: {bayesian.get('risk_level')}", styles['Normal']))
            story.append(Paragraph(f"• interpretation: {bayesian.get('interpretation')}", styles['Normal']))
            for factor in conflict.get('dominance_factors', []):
                story.append(Paragraph(f"• {factor}", styles['Normal']))

            calibration = explain_reasoning.get('4_bayesian_calibration_commentary', {})
            story.append(Paragraph("4. Bayesian Calibration Commentary", styles['Heading3']))
            story.append(Paragraph(f"Likelihood Overweighted: {calibration.get('likelihood_overweighted', False)}", styles['Normal']))
            story.append(Paragraph(f"{calibration.get('commentary', '')}", styles['Normal']))

            story.append(Paragraph("5. Unified Interpretation (Improved Classification)", styles['Heading3']))
            story.append(Paragraph(f"{explain_reasoning.get('5_unified_interpretation_improved_classification', 'INCONCLUSIVE')}", styles['Normal']))

            confidence = explain_reasoning.get('6_forensic_confidence_index', {})
            story.append(Paragraph("6. Forensic Confidence Index", styles['Heading3']))
            story.append(Paragraph(f"Level: {confidence.get('level', 'LOW')}", styles['Normal']))
            story.append(Paragraph(f"{confidence.get('basis', '')}", styles['Normal']))

            story.append(Paragraph("7. Narrative Forensic Summary", styles['Heading3']))
            story.append(Paragraph(f"{explain_reasoning.get('7_narrative_forensic_summary', '')}", styles['Normal']))
            story.append(Spacer(1, 12))

        # 3.7 Assist Suggestions (Assist Mode)
        assist = data.get('assist_suggestions', {})
        if assist:
            story.append(Paragraph("Assist Mode (Analyst Augmentation)", styles['Heading2']))
            story.append(Paragraph(f"Suggested Structural Finding: {assist.get('suggested_structural_finding', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Suggested Interpretation: {assist.get('suggested_interpretation', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Suggested Risk Level: {assist.get('suggested_risk_level', 'N/A')}", styles['Normal']))
            story.append(Paragraph("Suggested Follow-up:", styles['Normal']))
            for step in assist.get('suggested_follow_up', []):
                story.append(Paragraph(f"• {step}", styles['Normal']))
            story.append(Paragraph(f"Final Decision: {assist.get('final_decision', 'Pending Analyst Confirmation')}", styles['Normal']))
            story.append(Spacer(1, 12))

        # Flags/Issues
        flags = data.get('flags', [])
        if flags:
            story.append(Paragraph("Detected Issues", styles['Heading2']))
            for flag in flags:
                story.append(Paragraph(f"• <font color='red'>{flag}</font>", styles['Normal']))
            story.append(Spacer(1, 12))

        # Metadata Sections (hidden in explain mode to keep output non-technical)
        if not explain_mode:
            metadata = data.get('metadata', {}) or {}
            flat_metadata = ExifToolStyleFormatter._flatten_metadata(metadata)

            if flat_metadata:
                story.append(Paragraph("Comprehensive Metadata", styles['Heading2']))
                
                # Prepare data for the table, wrapping long values in Paragraphs
                normal_style = styles['Normal']
                normal_style.wordWrap = 'CJK' # Enable word wrapping
                # Mixed table cell types: header strings + Paragraph flowables.
                t_data: List[List[Any]] = [['Attribute', 'Value']]
                for key, value in sorted(flat_metadata.items()):
                    # Wrap both key and value in Paragraph objects to allow wrapping
                    key_p = Paragraph(self._compact_pdf_cell(key, max_chars=120), normal_style)
                    value_p = Paragraph(self._compact_pdf_cell(value, max_chars=400), normal_style)
                    t_data.append([key_p, value_p])
                
                # Create and style the table
                t = Table(t_data, colWidths=[200, 300], repeatRows=1)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP') # Align text to the top of the cell
                ]))
                story.append(t)

        doc.build(story)

    def _write_text(self, data: Dict[str, Any], path: Path) -> None:
        """Write data to text file using ExifTool-style formatting."""
        metadata = data.get('metadata', {})
        formatted_text = ExifToolStyleFormatter.format(metadata)
        history = data.get('modification_history', {})
        history_lines = []
        if isinstance(history, dict) and history:
            history_lines.append("=== MODIFICATION HISTORY ===")
            history_lines.append(f"Status              : {history.get('status', 'unknown')}")
            history_lines.append(f"Confidence          : {history.get('confidence', 'low')}")
            history_lines.append(f"Likely Modified     : {history.get('likely_modified', False)}")
            history_lines.append(f"Original Capture    : {history.get('original_capture_time', 'N/A')}")
            history_lines.append(f"Digitized Time      : {history.get('digitized_time', 'N/A')}")
            history_lines.append(f"File Modified Time  : {history.get('file_modified_time', 'N/A')}")
            history_lines.append(f"Summary             : {history.get('summary', 'No summary available.')}")
            software = history.get('software_detected', []) or []
            if software:
                history_lines.append(f"Software Detected   : {', '.join(str(item) for item in software)}")
            xmp_entries = history.get('xmp_history_entries', []) or []
            if xmp_entries:
                history_lines.append("XMP History Entries :")
                for item in xmp_entries:
                    history_lines.append(f"  - {item}")
            events = history.get('events', []) or []
            if events:
                history_lines.append("Events:")
                for event in events:
                    history_lines.append(
                        f"  - {event.get('event', 'N/A')} | {event.get('timestamp', 'N/A')} | {event.get('source', 'N/A')} | {event.get('confidence', 'N/A')} | {event.get('details', '')}"
                    )
        
        with open(path, 'w', encoding='utf-8') as f:
            if history_lines:
                f.write("\n".join(history_lines))
                f.write("\n\n")
            f.write(formatted_text)


__all__ = ['ForensicReportGenerator']
