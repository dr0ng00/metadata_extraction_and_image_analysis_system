"""Origin detector implementation.

Multi-signal origin classifier:
- EXIF camera fields
- JPEG quantization / re-encoding traces
- file structure markers (APP/XMP/ICC)
- natural sensor-noise proxy + demosaicing hints
- editing software indicators
- stripped metadata likelihood
- AI/synthetic indicators
"""
from __future__ import annotations

from typing import Any, Dict, List
import statistics

from PIL import Image, ImageFilter


class OriginDetector:
    """Detects digital image origin using forensic signal fusion."""

    CLASS_CAMERA = "Camera Captured Image"
    CLASS_EDITED = "Edited / Re-encoded Image"
    CLASS_AI = "AI Generated Image"
    CLASS_SYNTHETIC = "Synthetic Graphic / Illustration"
    CLASS_UNKNOWN = "Unknown Origin"

    def __init__(self):
        self.model = None

    def detect(self, metadata: Dict[str, Any], image_path: str | None = None) -> Dict[str, Any]:
        """Run origin detection and emit modern + legacy-compatible outputs."""
        if not metadata:
            return {'error': 'No metadata provided', 'primary_origin': 'unknown'}

        features = self._extract_features(metadata, image_path=image_path)
        decision = self._classify(features)

        return {
            'primary_origin': decision['legacy_label'],
            'confidence': decision['confidence_score'],
            'features': features,
            'details': decision['reasoning'],
            'is_synthetic': decision['final_classification'] in {self.CLASS_AI, self.CLASS_SYNTHETIC},
            'platform_fingerprint': features.get('platform_hint'),
            'final_classification': decision['final_classification'],
            'reasoning': decision['reasoning'],
            'evidence_used': decision['evidence_used'],
            'confidence_score': decision['confidence_score'],
            'forensic_signals_detected': decision['forensic_signals_detected'],
        }

    def _extract_features(self, metadata: Dict[str, Any], image_path: str | None = None) -> Dict[str, Any]:
        summary = self._as_dict(metadata.get('summary'))
        exif = self._as_dict(metadata.get('exif'))
        xmp = self._as_dict(metadata.get('xmp'))
        c2pa = self._as_dict(metadata.get('c2pa'))
        icc = self._as_dict(metadata.get('icc_profile'))
        image_info = self._as_dict(metadata.get('image_info'))
        raw_exiftool = self._as_dict(metadata.get('raw_exiftool'))

        software_fields = self._extract_software_fields(metadata)
        software_tokens = " | ".join(str(v).lower() for v in software_fields.values() if v)

        exif_presence = self._camera_exif_presence(summary=summary, exif=exif)
        camera_exif_strength = sum(exif_presence.values()) / 5.0
        metadata_density = len(exif)

        software_signals = self._score_software_signals(software_tokens)
        ai_meta_signals = self._score_ai_metadata_signals(software_tokens, xmp=xmp, c2pa=c2pa, exif=exif)
        metadata_stripped_likelihood = self._score_metadata_stripped(
            metadata_density=metadata_density,
            camera_exif_strength=camera_exif_strength,
            has_xmp=bool(xmp),
            has_icc=bool(icc),
        )
        structure = self._extract_file_structure_markers(exif=exif, xmp=xmp, icc=icc, raw_exiftool=raw_exiftool)
        visual = self._extract_visual_signals(image_path=image_path)
        qtables = self._extract_qtable_signals(image_path=image_path)
        demosaic_strength = self._score_demosaic_hints(exif=exif, raw_exiftool=raw_exiftool)

        reencode_strength = self._bounded(
            0.50 * qtables['software_qtable_score'] +
            0.25 * qtables['double_compression_score'] +
            0.15 * software_signals['platform_reencode_score'] +
            0.10 * metadata_stripped_likelihood
        )
        camera_pipeline_strength = self._bounded(
            0.40 * visual['natural_noise_score'] +
            0.30 * demosaic_strength +
            0.30 * structure['camera_structure_score']
        )
        synthetic_graphic_strength = self._bounded(
            0.45 * visual['smooth_gradient_score'] +
            0.35 * visual['uniform_texture_score'] +
            0.20 * (1.0 - camera_pipeline_strength)
        )
        ai_indicator_strength = self._bounded(
            0.70 * ai_meta_signals['ai_metadata_score'] +
            0.30 * visual['ai_frequency_anomaly_score']
        )
        edit_software_strength = self._bounded(
            0.70 * software_signals['editing_software_score'] +
            0.30 * structure['editing_container_score']
        )

        return {
            'software': software_tokens,
            'software_fields': software_fields,
            'metadata_density': metadata_density,
            'resolution': f"{image_info.get('width')}x{image_info.get('height')}",
            'aspect_ratio': round(image_info.get('width', 0) / image_info.get('height', 1), 2) if image_info.get('height') else 0.0,
            'dpi': exif.get('XResolution') or exif.get('Image XResolution'),
            'has_gps': bool(exif.get('GPSLatitude') or exif.get('GPS GPSLatitude')),
            'thumbnail_present': 'thumbnail' in " ".join(k.lower() for k in exif.keys()),
            'c2pa': c2pa,
            'platform_hint': software_signals['platform_hint'],
            'has_camera_make': bool(exif_presence['make']),
            'has_camera_model': bool(exif_presence['model']),
            'has_lens_model': bool(exif_presence['lens']),
            'has_datetime_original': bool(summary.get('datetime_original') or exif.get('DateTimeOriginal') or exif.get('EXIF DateTimeOriginal')),
            'camera_signature_strength': int(round(camera_exif_strength * 5)),
            'signal_vector': {
                'camera_exif_strength': camera_exif_strength,
                'camera_pipeline_strength': camera_pipeline_strength,
                'edit_software_strength': edit_software_strength,
                'reencode_strength': reencode_strength,
                'metadata_stripped_likelihood': metadata_stripped_likelihood,
                'synthetic_graphic_strength': synthetic_graphic_strength,
                'ai_indicator_strength': ai_indicator_strength,
                'conflict_level': self._estimate_conflict_level(
                    camera_exif_strength=camera_exif_strength,
                    camera_pipeline_strength=camera_pipeline_strength,
                    edit_software_strength=edit_software_strength,
                    reencode_strength=reencode_strength,
                    synthetic_graphic_strength=synthetic_graphic_strength,
                    ai_indicator_strength=ai_indicator_strength,
                ),
            },
            'raw_signals': {
                'exif_presence': exif_presence,
                'file_structure': structure,
                'visual': visual,
                'qtables': qtables,
                'software_signals': software_signals,
                'ai_meta_signals': ai_meta_signals,
                'demosaic_strength': demosaic_strength,
            }
        }

    def _classify(self, features: Dict[str, Any]) -> Dict[str, Any]:
        signals = features.get('signal_vector', {})
        camera_exif_strength = float(signals.get('camera_exif_strength', 0.0))
        camera_pipeline_strength = float(signals.get('camera_pipeline_strength', 0.0))
        edit_software_strength = float(signals.get('edit_software_strength', 0.0))
        reencode_strength = float(signals.get('reencode_strength', 0.0))
        metadata_stripped_likelihood = float(signals.get('metadata_stripped_likelihood', 0.0))
        synthetic_graphic_strength = float(signals.get('synthetic_graphic_strength', 0.0))
        ai_indicator_strength = float(signals.get('ai_indicator_strength', 0.0))
        conflict_level = float(signals.get('conflict_level', 0.0))

        evidence_used: List[str] = []
        if ai_indicator_strength >= 0.75 or (ai_indicator_strength >= 0.60 and camera_pipeline_strength < 0.35):
            final_class = self.CLASS_AI
            reasoning = "Strong AI-generation indicators detected from metadata/frequency signals."
            evidence_used.extend(self._evidence_for_ai(features))
        elif (
            camera_exif_strength >= 0.75 and
            camera_pipeline_strength >= 0.60 and
            edit_software_strength < 0.45 and
            reencode_strength < 0.45
        ):
            final_class = self.CLASS_CAMERA
            reasoning = "Strong camera EXIF fields and camera pipeline consistency with low editing/re-encoding evidence."
            evidence_used.extend(self._evidence_for_camera(features))
        elif (
            edit_software_strength >= 0.55 or
            reencode_strength >= 0.55 or
            (metadata_stripped_likelihood >= 0.60 and (reencode_strength >= 0.45 or edit_software_strength >= 0.45))
        ):
            final_class = self.CLASS_EDITED
            reasoning = "Editing or re-encoding traces are present; stripped metadata is not treated as camera evidence."
            evidence_used.extend(self._evidence_for_edited(features))
        elif (
            synthetic_graphic_strength >= 0.70 and
            camera_pipeline_strength < 0.35 and
            camera_exif_strength < 0.40 and
            ai_indicator_strength < 0.60
        ):
            final_class = self.CLASS_SYNTHETIC
            reasoning = "Visual/noise profile is non-photographic and lacks camera acquisition structure."
            evidence_used.extend(self._evidence_for_synthetic(features))
        else:
            final_class = self.CLASS_UNKNOWN
            reasoning = "Evidence is insufficient or conflicting for a definitive origin class."
            evidence_used.extend(self._evidence_for_unknown(features))

        confidence_score = self._estimate_confidence(
            final_class=final_class,
            camera_exif_strength=camera_exif_strength,
            camera_pipeline_strength=camera_pipeline_strength,
            edit_software_strength=edit_software_strength,
            reencode_strength=reencode_strength,
            synthetic_graphic_strength=synthetic_graphic_strength,
            ai_indicator_strength=ai_indicator_strength,
            conflict_level=conflict_level,
        )

        return {
            'final_classification': final_class,
            'legacy_label': self._to_legacy_label(final_class, features),
            'reasoning': reasoning,
            'evidence_used': self._dedupe(evidence_used),
            'confidence_score': confidence_score,
            'forensic_signals_detected': {k: round(float(v), 4) for k, v in signals.items()},
        }
    def _camera_exif_presence(self, summary: Dict[str, Any], exif: Dict[str, Any]) -> Dict[str, int]:
        has_make = bool(summary.get('camera_make') or exif.get('Make') or exif.get('Image Make') or exif.get('EXIF Make'))
        has_model = bool(summary.get('camera_model') or exif.get('Model') or exif.get('Image Model') or exif.get('EXIF Model'))
        has_lens = bool(exif.get('LensModel') or exif.get('EXIF LensModel') or exif.get('Lens Type'))
        has_exposure = bool(exif.get('ExposureTime') or exif.get('EXIF ExposureTime'))
        has_iso = bool(exif.get('ISOSpeedRatings') or exif.get('EXIF ISOSpeedRatings') or exif.get('ISO'))
        return {'make': int(has_make), 'model': int(has_model), 'lens': int(has_lens), 'exposure': int(has_exposure), 'iso': int(has_iso)}

    def _extract_software_fields(self, metadata: Dict[str, Any]) -> Dict[str, str]:
        exif = self._as_dict(metadata.get('exif'))
        summary = self._as_dict(metadata.get('summary'))
        xmp = self._as_dict(metadata.get('xmp'))

        candidates: List[str] = ['Software', 'ProcessingSoftware', 'CreatorTool', 'HistorySoftwareAgent', 'XMPToolkit']
        field_values: Dict[str, str] = {}
        for field in candidates:
            value = None
            for key in [field, f"Image {field}", f"EXIF {field}", f"XMP {field}", f"XMP:{field}"]:
                raw = exif.get(key)
                if raw:
                    value = str(raw).strip()
                    break
            if not value and field == 'Software' and summary.get('software'):
                value = str(summary.get('software')).strip()
            if not value and isinstance(xmp, dict):
                for k, v in xmp.items():
                    if field.lower() in str(k).lower() and v:
                        value = str(v).strip()
                        break
            if value:
                field_values[field] = value
        return field_values

    def _score_software_signals(self, software_tokens: str) -> Dict[str, Any]:
        s = (software_tokens or "").lower()
        editing_tokens = ['photoshop', 'lightroom', 'pixlr', 'inshot', 'picsart', 'snapseed', 'gimp', 'affinity', 'canva']
        platform_tokens = ['whatsapp', 'instagram', 'facebook', 'telegram', 'wechat', 'messenger']

        edit_hits = sum(1 for t in editing_tokens if t in s)
        platform_hits = sum(1 for t in platform_tokens if t in s)
        platform_hint = next((p for p in platform_tokens if p in s), None)

        return {
            'editing_software_score': self._bounded(edit_hits / 2.0),
            'platform_reencode_score': self._bounded(platform_hits / 2.0),
            'platform_hint': platform_hint,
        }

    def _score_ai_metadata_signals(self, software_tokens: str, xmp: Dict[str, Any], c2pa: Dict[str, Any], exif: Dict[str, Any]) -> Dict[str, float]:
        text_blob = " | ".join(
            [software_tokens]
            + [f"{k}:{v}" for k, v in xmp.items()]
            + [f"{k}:{v}" for k, v in c2pa.items()]
            + [f"{k}:{v}" for k, v in exif.items() if 'prompt' in str(k).lower() or 'generator' in str(k).lower()]
        ).lower()
        ai_tokens = ['dall-e', 'midjourney', 'stable diffusion', 'sdxl', 'ai generated', 'generative', 'comfyui', 'automatic1111', 'firefly', 'chatgpt', 'gpt-4o']
        hits = sum(1 for t in ai_tokens if t in text_blob)
        c2pa_source = str(c2pa.get('Actions Digital Source Type', '')).lower()
        c2pa_ai = 1.0 if 'trainedalgorithmicmedia' in c2pa_source else 0.0
        return {'ai_metadata_score': self._bounded(max(c2pa_ai, hits / 2.0))}

    def _score_metadata_stripped(self, metadata_density: int, camera_exif_strength: float, has_xmp: bool, has_icc: bool) -> float:
        base = 0.0
        if metadata_density <= 1:
            base += 0.65
        elif metadata_density <= 3:
            base += 0.40
        elif metadata_density <= 6:
            base += 0.20
        base += 0.35 * (1.0 - camera_exif_strength)
        if has_xmp:
            base -= 0.10
        if has_icc:
            base -= 0.05
        return self._bounded(base)

    def _extract_file_structure_markers(self, exif: Dict[str, Any], xmp: Dict[str, Any], icc: Dict[str, Any], raw_exiftool: Dict[str, Any]) -> Dict[str, float]:
        all_keys = " | ".join(list(exif.keys()) + list(raw_exiftool.keys())).lower()
        has_app0_jfif = int(any(k in all_keys for k in ['jfif', 'app0']))
        has_app1_exif = int(any(k in all_keys for k in ['exif', 'app1']))
        has_xmp = int(bool(xmp))
        has_icc = int(bool(icc))
        has_dqt = int(any(k in all_keys for k in ['dqt', 'quantization']))

        camera_structure = self._bounded(0.30 * has_app0_jfif + 0.35 * has_app1_exif + 0.20 * has_dqt + 0.15 * has_icc)
        editing_container = self._bounded(0.50 * has_xmp + 0.25 * has_icc + 0.25 * int('creatortool' in all_keys or 'historysoftwareagent' in all_keys))
        return {'camera_structure_score': camera_structure, 'editing_container_score': editing_container}

    def _extract_qtable_signals(self, image_path: str | None) -> Dict[str, float]:
        if not image_path:
            return {'software_qtable_score': 0.0, 'double_compression_score': 0.0}
        try:
            with Image.open(image_path) as img:
                if str(img.format).upper() != 'JPEG':
                    return {'software_qtable_score': 0.0, 'double_compression_score': 0.0}
                qtables = getattr(img, 'quantization', {}) or {}
                luma = list(qtables.get(0, []))
                if not luma:
                    return {'software_qtable_score': 0.0, 'double_compression_score': 0.0}
                very_low = sum(1 for x in luma[:16] if x <= 3)
                sharp_steps = sum(1 for i in range(1, min(len(luma), 32)) if abs(luma[i] - luma[i - 1]) >= 20)
                software_qtable = self._bounded(0.12 * very_low + 0.08 * sharp_steps)
                double_compression = self._bounded(0.05 * sum(1 for x in luma[:32] if x % 2 == 1))
                return {'software_qtable_score': software_qtable, 'double_compression_score': double_compression}
        except Exception:
            return {'software_qtable_score': 0.0, 'double_compression_score': 0.0}

    def _extract_visual_signals(self, image_path: str | None) -> Dict[str, float]:
        if not image_path:
            return {'natural_noise_score': 0.0, 'smooth_gradient_score': 0.0, 'uniform_texture_score': 0.0, 'ai_frequency_anomaly_score': 0.0}
        try:
            with Image.open(image_path) as img:
                gray = img.convert('L')
                max_side = max(gray.size)
                if max_side > 1024:
                    scale = 1024.0 / max_side
                    gray = gray.resize((max(1, int(gray.size[0] * scale)), max(1, int(gray.size[1] * scale))))

                pixel_count = gray.width * gray.height
                gray_data = gray.getdata()
                pixels = [self._pixel_to_int(gray_data[i]) for i in range(pixel_count)]
                blur = gray.filter(ImageFilter.GaussianBlur(radius=1.2))
                blur_data = blur.getdata()
                residual = [abs(pixels[i] - self._pixel_to_int(blur_data[i])) for i in range(pixel_count)]
                noise_std = statistics.pstdev(residual) if len(residual) > 1 else 0.0

                natural_noise_score = self._bounded(1.0 - abs(noise_std - 8.0) / 8.0)
                smooth_gradient_score = self._bounded(max(0.0, (5.0 - noise_std) / 5.0))
                unique_tones = len(set(pixels))
                uniform_texture_score = self._bounded(max(0.0, (80.0 - min(unique_tones, 80)) / 80.0))

                edge = gray.filter(ImageFilter.FIND_EDGES)
                edge_data = edge.getdata()
                edge_vals = [self._pixel_to_int(edge_data[i]) for i in range(pixel_count)]
                edge_std = statistics.pstdev(edge_vals) if len(edge_vals) > 1 else 0.0
                ai_frequency_anomaly_score = self._bounded(max(0.0, (18.0 - edge_std) / 18.0))

                return {
                    'natural_noise_score': natural_noise_score,
                    'smooth_gradient_score': smooth_gradient_score,
                    'uniform_texture_score': uniform_texture_score,
                    'ai_frequency_anomaly_score': ai_frequency_anomaly_score,
                }
        except Exception:
            return {'natural_noise_score': 0.0, 'smooth_gradient_score': 0.0, 'uniform_texture_score': 0.0, 'ai_frequency_anomaly_score': 0.0}

    def _score_demosaic_hints(self, exif: Dict[str, Any], raw_exiftool: Dict[str, Any]) -> float:
        keys = " | ".join([str(k).lower() for k in list(exif.keys()) + list(raw_exiftool.keys())])
        hints = ['cfapattern', 'bayer', 'blacklevel', 'whitelinear', 'colormatrix', 'makernotes']
        hits = sum(1 for h in hints if h in keys)
        return self._bounded(hits / 3.0)

    def _estimate_conflict_level(self, camera_exif_strength: float, camera_pipeline_strength: float, edit_software_strength: float, reencode_strength: float, synthetic_graphic_strength: float, ai_indicator_strength: float) -> float:
        c1 = 1.0 if (camera_exif_strength > 0.7 and (edit_software_strength > 0.6 or reencode_strength > 0.6)) else 0.0
        c2 = 1.0 if (camera_pipeline_strength > 0.6 and ai_indicator_strength > 0.6) else 0.0
        c3 = 1.0 if (synthetic_graphic_strength > 0.7 and camera_exif_strength > 0.7) else 0.0
        return self._bounded((c1 + c2 + c3) / 2.0)

    def _estimate_confidence(self, final_class: str, camera_exif_strength: float, camera_pipeline_strength: float, edit_software_strength: float, reencode_strength: float, synthetic_graphic_strength: float, ai_indicator_strength: float, conflict_level: float) -> float:
        if final_class == self.CLASS_CAMERA:
            score = 0.60 + 0.20 * camera_exif_strength + 0.20 * camera_pipeline_strength
        elif final_class == self.CLASS_EDITED:
            score = 0.58 + 0.22 * max(edit_software_strength, reencode_strength) + 0.10 * reencode_strength
        elif final_class == self.CLASS_AI:
            score = 0.62 + 0.30 * ai_indicator_strength
        elif final_class == self.CLASS_SYNTHETIC:
            score = 0.56 + 0.30 * synthetic_graphic_strength
        else:
            score = 0.40 + 0.20 * (1.0 - conflict_level)
        score -= 0.15 * conflict_level
        return round(self._bounded(score), 4)

    def _to_legacy_label(self, final_class: str, features: Dict[str, Any]) -> str:
        if final_class == self.CLASS_CAMERA:
            return 'camera_original'
        if final_class == self.CLASS_EDITED:
            signals = features.get('signal_vector', {})
            if float(signals.get('camera_exif_strength', 0.0)) >= 0.75:
                return 'camera_post_processed'
            return 'software_reencoded'
        if final_class == self.CLASS_AI:
            return 'synthetic_ai_generated'
        if final_class == self.CLASS_SYNTHETIC:
            return 'software_generated'
        return 'origin_unverified'

    def _evidence_for_ai(self, features: Dict[str, Any]) -> List[str]:
        raw = features.get('raw_signals', {})
        out: List[str] = []
        if raw.get('ai_meta_signals', {}).get('ai_metadata_score', 0) > 0:
            out.append("AI metadata signature matched known generative tool/provenance marker.")
        if raw.get('visual', {}).get('ai_frequency_anomaly_score', 0) > 0.4:
            out.append("Abnormal frequency/edge behavior detected.")
        return out or ["AI evidence threshold exceeded."]

    def _evidence_for_camera(self, features: Dict[str, Any]) -> List[str]:
        exif_presence = features.get('raw_signals', {}).get('exif_presence', {})
        out = []
        if exif_presence.get('make') and exif_presence.get('model'):
            out.append("Camera Make/Model present.")
        if exif_presence.get('lens'):
            out.append("LensModel present.")
        if exif_presence.get('exposure') and exif_presence.get('iso'):
            out.append("ExposureTime and ISO present.")
        out.append("Camera pipeline consistency from noise/demosaic/structure signals.")
        return out

    def _evidence_for_edited(self, features: Dict[str, Any]) -> List[str]:
        signals = features.get('signal_vector', {})
        raw = features.get('raw_signals', {})
        out = []
        if signals.get('metadata_stripped_likelihood', 0) >= 0.60:
            out.append("Metadata appears stripped or sparse.")
        if raw.get('software_signals', {}).get('editing_software_score', 0) > 0:
            out.append("Editing software markers detected.")
        if signals.get('reencode_strength', 0) >= 0.45:
            out.append("Compression/re-encoding indicators detected.")
        return out or ["Re-encoding/editing evidence exceeded decision threshold."]

    def _evidence_for_synthetic(self, features: Dict[str, Any]) -> List[str]:
        return [
            "Smooth gradients and uniform digital textures detected.",
            "No strong camera-pipeline evidence (sensor noise/demosaicing/EXIF core fields).",
        ]

    def _evidence_for_unknown(self, features: Dict[str, Any]) -> List[str]:
        signals = features.get('signal_vector', {})
        if float(signals.get('conflict_level', 0.0)) >= 0.5:
            return ["Competing signals conflict across camera/edited/synthetic hypotheses."]
        return ["Insufficient signal strength for a definitive origin class."]

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _pixel_to_int(self, value: Any) -> int:
        if isinstance(value, tuple):
            return int(value[0]) if value else 0
        if value is None:
            return 0
        return int(value)

    def _bounded(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    def _dedupe(self, items: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for item in items:
            if item not in seen:
                out.append(item)
                seen.add(item)
        return out


__all__ = ['OriginDetector']
