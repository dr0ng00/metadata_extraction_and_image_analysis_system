"""Natural language processing utilities.

Provides `NaturalLanguageProcessor` for basic intent parsing and response generation,
simulating the XAI/NLP layer in the architecture.
"""
from typing import Any, Dict, Optional


class NaturalLanguageProcessor:
    """NLP engine for parsing user queries and generating human-readable responses."""

    def __init__(self, model: Any | None = None):
        self.model = model
        self.current_mode = 'explain_forensic' # Default to high-integrity examiner mode
        self.jargon_map = {
            'EXIF': 'Image Metadata',
            'XMP': 'Extended Metadata',
            'IPTC': 'Media Metadata',
            'bitstream': 'digital file data',
            'heuristics': 'analysis rules',
            'quantization': 'compression',
            'bit': 'data point',
            'MakerNotes': 'Manufacturer Data'
        }

    def set_mode(self, mode: str) -> bool:
        """Update the active explanation mode."""
        valid_modes = ['explain_basic', 'explain_forensic', 'explain_security', 'explain_legal']
        if mode in valid_modes:
            self.current_mode = mode
            return True
        return False

    def _filter_jargon(self, text: str) -> str:
        """Replace technical terms with plain-language equivalents for legal mode."""
        if self.current_mode != 'explain_legal':
            return text
        
        filtered = text
        for tech, plain in self.jargon_map.items():
            filtered = filtered.replace(tech, plain)
        return filtered

    def parse(self, text: str) -> Dict[str, Any]:
        """Parse user text into intent and entities."""
        text = text.lower()
        intent = 'unknown'
        entities = {}

        if any(w in text for w in ['fake', 'real', 'authentic', 'forged', 'valid']):
            intent = 'verify_authenticity'
        elif any(w in text for w in ['date', 'time', 'when']):
            intent = 'check_dates'
        elif any(w in text for w in ['camera', 'device', 'phone', 'model']):
            intent = 'check_device'
        elif any(w in text for w in ['summary', 'report', 'results']):
            intent = 'generate_summary'
        elif any(w in text for w in ['dimension', 'size', 'resolution', 'width', 'height']):
            intent = 'check_dimensions'
        elif any(w in text for w in ['format', 'type', 'extension', 'filetype']):
            intent = 'check_format'
        elif any(w in text for w in ['software', 'editor', 'photoshop', 'gimp']):
            intent = 'check_software'
        elif any(w in text for w in ['origin', 'source', 'where']):
            intent = 'check_origin'
        elif any(w in text for w in ['location', 'gps', 'coordinates', 'map', 'place']):
            intent = 'check_location'
        if any(w in text for w in ['risk', 'score', 'danger']):
            intent = 'explain_risk'
        elif any(w in text for w in ['conflict', 'correlation', 'unified', 'conclusion']):
            intent = 'check_correlation'
        elif any(w in text for w in ['explain', 'why', 'how', 'details']):
            intent = 'get_explanations'
        
        # New: Identify specific forensic tools/commands
        if any(w in text for w in ['exiftool', 'volatility', 'strings', 'grep', 'grep_search', 'hash', 'sha256']):
            intent = 'explain_tool'
            entities['tool'] = next(w for w in ['exiftool', 'volatility', 'strings', 'grep', 'hash'] if w in text)

        return {'intent': intent, 'entities': entities, 'text': text}

    def respond(self, intent: str, context: Dict[str, Any] | None = None) -> str:
        """
        Generate a professional, structured forensic explanation based on intent and context.
        Mandatory Format: TITLE, WHAT IT DOES, HOW IT WORKS, RELEVANCE, LIMITATIONS, RISKS, NEXT STEPS.
        """
        if not context:
            return "ERROR: Insufficient context for forensic analysis. An analyzed image dataset is required."

        # Dynamic section filtering based on active mode
        mode_config = {
            'explain_basic': ['WHAT_IT_DOES', 'HOW_IT_WORKS'],
            'explain_forensic': ['WHAT_IT_DOES', 'HOW_IT_WORKS', 'FORENSIC_OR_SECURITY_RELEVANCE', 'LIMITATIONS', 'RISKS_OR_CAUTIONS', 'NEXT_ANALYTICAL_STEPS'],
            'explain_security': ['WHAT_IT_DOES', 'HOW_IT_WORKS', 'FORENSIC_OR_SECURITY_RELEVANCE', 'RISKS_OR_CAUTIONS'],
            'explain_legal': ['WHAT_IT_DOES', 'LIMITATIONS', 'RISKS_OR_CAUTIONS']
        }
        active_sections = mode_config.get(self.current_mode, mode_config['explain_forensic'])

        # Template for structured response
        def format_narrative(title: str, what: str, how: str, relevance: str, limitations: str, risks: str, next_steps: str) -> str:
            narrative = f"TITLE:\n{title}\n\n"
            
            sections = {
                'WHAT_IT_DOES': f"WHAT IT DOES:\n{what}\n\n",
                'HOW_IT_WORKS': f"HOW IT WORKS:\n{how}\n\n",
                'FORENSIC_OR_SECURITY_RELEVANCE': f"FORENSIC / SECURITY RELEVANCE:\n{relevance}\n\n",
                'LIMITATIONS': f"LIMITATIONS:\n{limitations}\n\n",
                'RISKS_OR_CAUTIONS': f"RISKS / CAUTIONS:\n{risks}\n\n",
                'NEXT_ANALYTICAL_STEPS': f"NEXT ANALYTICAL STEPS (NON-ACTIONABLE):\n{next_steps}"
            }
            
            for section_code in active_sections:
                if section_code in sections:
                    narrative += sections[section_code]
            
            return self._filter_jargon(narrative.strip())

        if intent == 'verify_authenticity':
            risk = context.get('risk_assessment', {})
            score = risk.get('risk_score', 0)
            level = risk.get('level', 'UNKNOWN')
            return format_narrative(
                "Image Authenticity Verification Audit",
                "Evaluates the probability of metadata manipulation and structural integrity.",
                f"Analysis of EXIF/XMP consistency resulted in a risk score of {score:.1f}/100.",
                "Determines the admissibility and reliability of the digital evidence.",
                "Cannot detect advanced pixel-perfect deepfakes without heuristic noise analysis.",
                "False positives may occur in images re-saved by legitimate software.",
                "Perform ELA (Error Level Analysis) to verify compression consistency."
            )

        if intent == 'check_dates':
            meta = context.get('metadata', {}).get('summary', {})
            original = meta.get('datetime_original', 'Unknown')
            return format_narrative(
                "Chronological Metadata Fingerprint Analysis",
                "Extracts and validates the primary temporal markers from the image bitstream.",
                f"The 'DateTimeOriginal' field identifies a capture time of {original}.",
                "Establishes a timeline of events for investigative plotting.",
                "Metadata timestamps can be manually altered (anti-forensics).",
                "Timestamps do not prove the physical location of the device at that time.",
                "Correlate capture time with file system 'MTime' and 'CTime' for anomalies."
            )

        if intent == 'check_device':
            meta = context.get('metadata', {}).get('summary', {})
            make = meta.get('camera_make', 'Unknown')
            model = meta.get('camera_model', 'Unknown')
            return format_narrative(
                "Hardware Source Signature Identification",
                "Identifies the physical device used to capture the digital asset.",
                f"The Make/Model tags indicate a {make} {model} hardware signature.",
                "Links evidence to a specific physical device or manufacturer class.",
                "MakerNotes and Model tags can be stripped or spoofed.",
                "Generic profiles (e.g., 'Apple') do not identify a specific serial number.",
                "Check for embedded lens data or unique sensor noise patterns."
            )

        if intent == 'check_dimensions':
            meta = context.get('metadata', {}).get('summary', {})
            dims = meta.get('dimensions', 'Unknown')
            return format_narrative(
                "Image Dimensional Analysis",
                "Extracts the pixel width and height of the evidence file.",
                f"The image dimensions are {dims}.",
                "Establishes the resolution and aspect ratio, which can be compared against known camera sensor outputs or social media platform standards.",
                "Dimensions can be altered by cropping or resizing, which may not be directly detectable from this data alone.",
                "Unusual or non-standard aspect ratios can be an indicator of post-capture modification (cropping).",
                "Correlate dimensions with camera model specifications and known platform resizing standards."
            )

        if intent == 'check_format':
            meta = context.get('metadata', {}).get('summary', {})
            file_format = meta.get('format', 'Unknown')
            return format_narrative(
                "File Format and Encoding Analysis",
                "Identifies the file container type (e.g., JPEG, PNG, HEIC) of the evidence.",
                f"The evidence is encoded as a {file_format} file.",
                "The file format dictates which forensic analysis modules are applicable (e.g., Quantization Table analysis for JPEG).",
                "The file extension can be misleading; this analysis relies on the file's internal header signature.",
                "A file saved in a different format than its original capture (e.g., a camera RAW saved as JPEG) is a sign of processing.",
                "Analyze compression artifacts and metadata specific to the identified format."
            )

        if intent == 'check_software':
            meta = context.get('metadata', {}).get('summary', {})
            software = meta.get('software', 'None Detected')
            return format_narrative(
                "Software Signature Audit",
                "Scans metadata for tags identifying processing software (e.g., Photoshop, GIMP).",
                f"The 'Software' metadata tag reports: '{software}'.",
                "The presence of editing software is a primary indicator that the image is not a camera original and has been modified.",
                "This tag can be stripped or altered, so its absence does not guarantee authenticity.",
                "A software signature proves the digital chain of custody was broken by an external program, increasing manipulation risk.",
                "Correlate with Quantization Table analysis to find independent signal-layer evidence of software re-saving."
            )

        if intent == 'check_origin':
            origin = context.get('origin_detection', {})
            platform = origin.get('platform_fingerprint', 'Mobile/Internal')
            return format_narrative(
                "Evidence Origin System Audit",
                "Determines the platform source (e.g., Social Media, Camera) of the image.",
                f"Fingerprint analysis points to {platform} as the probable source system.",
                "Verifies the systemic context of the evidence capture, independent of its content.",
                "Does not determine geographic location, only the system that last processed the file.",
                "Platform fingerprints can be ambiguous for heavily processed or stripped files.",
                "Correlate with metadata analysis to confirm findings."
            )

        if intent == 'check_location':
            location = context.get('metadata', {}).get('location')
            inferred_location = context.get('contextual_analysis', {}).get('inferred_location')

            if location:
                # Direct GPS data is available and resolved
                location_name = location.get('location_name', 'Not available')
                return f"GEOSPATIAL REPORT (FROM EMBEDDED GPS):\n- Location Name: {location_name}\n- Coordinates: {location.get('coordinates', 'N/A')}\n- City: {location.get('city', 'N/A')}\n- Country: {location.get('country', 'N/A')} ({location.get('country_code', 'N/A')})\n- Full Address: {location.get('full_address', 'N/A')}"
            elif inferred_location:
                # Inferred location from other metadata
                return format_narrative(
                    "Inferred Geospatial Origin Analysis",
                    "Infers a probable geographic region from non-GPS metadata like TimeZoneOffset.",
                    f"Analysis of indirect metadata suggests a probable origin in: {inferred_location.get('region', 'Unknown')}. (Source: {inferred_location.get('source', 'N/A')})",
                    "Provides regional context when precise GPS is absent, crucial for narrowing down investigative scope.",
                    "This is an inference, not a precise coordinate. It is based on device settings which could be incorrect or manually set.",
                    "A mismatched timezone can be an indicator of anti-forensic activity.",
                    "Correlate this finding with visual content analysis (e.g., language on signs, landmarks) to increase confidence."
                )
            else:
                # No location data of any kind was found
                return "GEOSPATIAL REPORT: No direct or inferred location data was found in the evidence file. The system could not determine a geographic origin from the available metadata."

        if intent == 'explain_risk':
            risk = context.get('risk_assessment', {})
            return format_narrative(
                "Weighted Forensic Risk Assessment",
                "Provides a mathematical confidence interval for evidentiary manipulation.",
                f"Combines Authenticity, Origin, and Contextual scores ({risk.get('risk_score', 0)}/100).",
                "Quantifies the 'Benefit of Doubt' regarding evidence tampering.",
                "Weighted scores are based on predefined heuristics and may vary by domain.",
                "Risk scores are indicators, not absolute proofs of guilt or innocence.",
                "Review individual high-severity flags in the detailed justifications."
            )

        if intent == 'get_explanations' or intent == 'generate_summary':
            explanations = context.get('explanations', [])
            summary_txt = f"Total of {len(explanations)} forensic findings identified."
            return format_narrative(
                "Consolidated Forensic Justification Summary",
                "Aggregates explainable findings into a structured expert narrative.",
                "Cross-references multiple analysis modules for unified interpretation.",
                "Provides the human-readable evidence for legal documentation.",
                "Limited to findings where direct metadata triggers were identified.",
                "Summaries may omit low-severity noise encountered during extraction.",
                "Examine the 'Forensic Fact Sheets' for individual point-by-point logic."
            )

        if intent == 'explain_tool':
            tool = context.get('entities', {}).get('tool', 'Unknown Tool') if context else 'Unknown Tool'
            return self._get_tool_explanation(tool)

        return "UNKNOWN INTENT: The request cannot be mapped to a structured forensic analytical intent."

    def _get_tool_explanation(self, tool: str) -> str:
        """Provide structured 7-point narratives for forensic tools."""
        
        def format_narrative(title: str, what: str, how: str, relevance: str, limitations: str, risks: str, next_steps: str) -> str:
            return (
                f"TITLE:\n{title}\n\n"
                f"WHAT IT DOES:\n{what}\n\n"
                f"HOW IT WORKS:\n{how}\n\n"
                f"FORENSIC / SECURITY RELEVANCE:\n{relevance}\n\n"
                f"LIMITATIONS:\n{limitations}\n\n"
                f"RISKS / CAUTIONS:\n{risks}\n\n"
                f"NEXT ANALYTICAL STEPS (NON-ACTIONABLE):\n{next_steps}"
            )

        if 'exiftool' in tool:
            return format_narrative(
                "ExifTool Metadata Extraction Utility",
                "A platform-independent command-line application for reading, writing, and editing meta information in a wide variety of files.",
                "Directly parses the binary structure of file headers to extract EXIF, IPTC, XMP, and MakerNotes tags.",
                "Extracts capture parameters, hardware signatures, and timestamps critical for authenticity verification.",
                "Cannot prove the truth of the metadata it extracts; it only reads what is present in the bits.",
                "Writing or editing metadata with ExifTool modifies the file bitstream, potentially contaminating electronic evidence.",
                "Compare extracted 'MakerNotes' with standard manufacturer profiles for discrepancies."
            )
            
        if 'strings' in tool:
            return format_narrative(
                "Binary String Extraction (GNU Strings)",
                "Scans files for sequences of printable characters and outputs them to the console.",
                "Iterates through the raw binary data, identifying bytes that fall within the ASCII/UTF-8 printable range.",
                "Reveals embedded URLs, hardcoded paths, or developer comments in obscure binary formats.",
                "Produces significant 'noise' (random character sequences) and provides no context for where the string resides.",
                "Reading large files with strings consumes significant system memory if not piped correctly.",
                "Filter findings using regular expressions to identify specific patterns like IP addresses or dates."
            )

        if 'grep' in tool:
            return format_narrative(
                "GREP Pattern Matching Engine",
                "Searches plain-text data sets for lines that match a specific regular expression or string pattern.",
                "Uses an optimized search algorithm to scan input streams line-by-line against a user-defined pattern.",
                "Quickly identifies specific indicators of compromise (IoC) or keywords within log files or memory dumps.",
                "Limited to textual data; cannot natively search compressed or encrypted bitstreams.",
                "Improper regular expressions can lead to catastrophic backtracking or false negative results.",
                "Execute multi-line context searches (-A / -B flags) to understand the surrounding activity of a match."
            )

        return format_narrative(
            "Generic Forensic Tool / Utility",
            "A specialized application designed for investigative analysis of digital assets.",
            "Operates on specific file structures or system artifacts using predefined logic.",
            "Provides the technical basis for evidentiary findings and expert testimony.",
            "Tool efficacy depends on the version used and the integrity of the input data.",
            "Tools must be validated against known-good benchmarks to ensure court admissibility.",
            "Document the exact tool version and command parameters used in the forensic log."
        )

        return "I'm not sure how to answer that specifically. Try asking about 'risk', 'origin', 'authenticity', or 'details'."


__all__ = ['NaturalLanguageProcessor']
