from datetime import datetime

# --------------------------------------------------
# Configuration
# --------------------------------------------------

TIME_FIELDS = [
    "DateTimeOriginal",
    "CreateDate",
    "ModifyDate"
]

SUSPICIOUS_SOFTWARE_KEYWORDS = [
    "photoshop",
    "gimp",
    "lightroom",
    "snapseed",
    "canva"
]

EXIF_REQUIRED_CAMERA_FIELDS = [
    "Make",
    "Model",
    "ExifImageWidth",
    "ExifImageHeight",
    "DateTimeOriginal",
    "FNumber",
    "ExposureTime",
    "FocalLength",
    "ISO"
]

# --------------------------------------------------
# Helper Functions
# --------------------------------------------------

def parse_datetime(value):
    try:
        return datetime.strptime(value, "%Y:%m:%d %H:%M:%S")
    except Exception:
        return None


def analyze_timestamps(times):
    flags = []
    insights = {}

    if len(times) < 2:
        flags.append("Limited timestamp data for comparison")
        return flags, insights

    time_values = list(times.values())

    expected_order = ["DateTimeOriginal", "CreateDate", "ModifyDate"]
    available_times = [(k, v) for k, v in times.items() if k in expected_order]

    for i in range(len(available_times) - 1):
        curr_field, curr_time = available_times[i]
        next_field, next_time = available_times[i + 1]
        if curr_time > next_time:
            flags.append(f"Reverse chronology: {curr_field} > {next_field}")

    now = datetime.now()
    for field, ts in times.items():
        if ts > now:
            flags.append(f"Future timestamp detected: {field}")
        elif ts.year < 1990:
            flags.append(f"Pre-digital era timestamp: {field} ({ts.year})")

    diffs = []
    for i in range(len(time_values)):
        for j in range(i + 1, len(time_values)):
            diffs.append(abs((time_values[i] - time_values[j]).total_seconds()))

    if diffs:
        insights["max_time_diff_seconds"] = max(diffs)
        if max(diffs) > 86400:
            flags.append("Large timestamp discrepancies (>24 hours)")

    return flags, insights


def check_exif_completeness(metadata):
    flags = []

    present = [
        f for f in EXIF_REQUIRED_CAMERA_FIELDS
        if f in metadata and metadata[f]
    ]

    completeness = len(present) / len(EXIF_REQUIRED_CAMERA_FIELDS)

    if completeness < 0.3:
        flags.append(f"Low EXIF completeness ({completeness:.0%}) - possible metadata stripping")
    elif completeness > 0.8:
        flags.append("High EXIF completeness - likely original camera file")

    if ("GPSLatitude" not in metadata or not metadata.get("GPSLatitude")) and completeness > 0.5:
        flags.append("GPS data missing but other EXIF intact")

    return flags, {"exif_completeness": completeness}


def analyze_compression(metadata):
    flags = []
    insights = {}

    compression = metadata.get("Compression")
    if compression:
        insights["compression_type"] = compression
        if compression not in [6, 7]:
            flags.append(f"Unusual compression type: {compression}")

    quality = metadata.get("Quality")
    if quality:
        insights["estimated_quality"] = quality
        if quality < 50:
            flags.append(f"Low JPEG quality: {quality}")
        elif quality > 95:
            flags.append("Very high JPEG quality - possible re-save")

    sampling = metadata.get("YCbCrSubSampling")
    if sampling:
        insights["chroma_subsampling"] = sampling
        if sampling not in ["2 2", "1 1"]:
            flags.append(f"Atypical chroma subsampling: {sampling}")

    return flags, insights


def check_camera_consistency(metadata):
    flags = []

    make = metadata.get("Make", "").lower()
    width = metadata.get("ImageWidth")
    height = metadata.get("ImageHeight")

    if width and height and make:
        mp = (width * height) / 1_000_000

        ranges = {
            "canon": (8, 50),
            "nikon": (10, 46),
            "sony": (12, 61),
            "apple": (8, 12),
            "samsung": (12, 200),
        }

        for brand, (low, high) in ranges.items():
            if brand in make:
                if mp < low:
                    flags.append(f"Unusually low resolution for {make} ({mp:.1f}MP)")
                elif mp > high:
                    flags.append(f"Unusually high resolution for {make} ({mp:.1f}MP)")
                break

    exposure = metadata.get("ExposureTime")
    iso = metadata.get("ISO")

    if exposure and iso:
        try:
            exp = float(eval(exposure))
            if exp > 1 and iso < 200:
                flags.append(f"Long exposure ({exposure}s) with low ISO ({iso})")
        except Exception:
            pass

    return flags

# --------------------------------------------------
# MAIN NORMALIZATION FUNCTION (FINAL)
# --------------------------------------------------

def normalize_metadata_enhanced(metadata):
    normalized = {}
    flags = []
    insights = {}

    # Camera info
    normalized["Make"] = metadata.get("Make")
    normalized["Model"] = metadata.get("Model")

    if not normalized["Make"] or not normalized["Model"]:
        flags.append("Missing camera make/model")

    # Software analysis
    software = metadata.get("Software")
    normalized["Software"] = software

    if software:
        for tool in SUSPICIOUS_SOFTWARE_KEYWORDS:
            if tool in software.lower():
                flags.append(f"Edited using software: {software}")
                break

        if "adobe" in software.lower() and "apple" in normalized.get("Make", "").lower():
            flags.append("Adobe software used on Apple device image")

    # Timestamp analysis
    times = {}
    for field in TIME_FIELDS:
        parsed = parse_datetime(metadata.get(field))
        if parsed:
            times[field] = parsed

    normalized["Timestamps"] = {k: v.isoformat() for k, v in times.items()}
    t_flags, t_insights = analyze_timestamps(times)
    flags.extend(t_flags)
    insights.update(t_insights)

    # GPS analysis
    lat = metadata.get("GPSLatitude")
    lon = metadata.get("GPSLongitude")
    alt = metadata.get("GPSAltitude")

    if lat is not None and lon is not None:
        normalized["GPS"] = {"lat": lat, "lon": lon, "alt": alt}
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            flags.append("Invalid GPS coordinates")
        if abs(lat) < 0.001 and abs(lon) < 0.001:
            flags.append("GPS coordinates at origin (0,0)")
    else:
        normalized["GPS"] = None

    # Resolution & aspect ratio
    w = metadata.get("ImageWidth")
    h = metadata.get("ImageHeight")

    if w and h:
        normalized["Resolution"] = f"{w}x{h}"
        normalized["Megapixels"] = (w * h) / 1_000_000

        aspect = w / h
        if not any(abs(aspect - r) < 0.01 for r in [4/3, 3/2, 16/9, 1]):
            flags.append(f"Uncommon aspect ratio: {aspect:.2f}")

    # Advanced checks
    e_flags, e_insights = check_exif_completeness(metadata)
    flags.extend(e_flags)
    insights.update(e_insights)

    c_flags, c_insights = analyze_compression(metadata)
    flags.extend(c_flags)
    insights.update(c_insights)

    flags.extend(check_camera_consistency(metadata))

    # Metadata size
    normalized["field_count"] = len(metadata)
    if len(metadata) < 20:
        flags.append("Minimal metadata fields")
    elif len(metadata) > 200:
        flags.append("Excessive metadata fields")

    # Suspicion scoring
    score = 0
    for f in flags:
        if any(k in f for k in ["Edited using", "Reverse chronology", "Invalid GPS"]):
            score += 3
        elif any(k in f for k in ["Inconsistent", "Low EXIF"]):
            score += 2
        else:
            score += 1

    return {
        "normalized_metadata": normalized,
        "forensic_flags": flags,
        "forensic_insights": insights,
        "suspicion_score": score,
        "suspicion_level": "High" if score >= 8 else "Medium" if score >= 4 else "Low"
    }

# --------------------------------------------------
# Backward-compatible API for main.py
# --------------------------------------------------

def normalize_metadata(metadata: dict) -> dict:
    """
    Standard entry point used by main.py
    """
    return normalize_metadata_enhanced(metadata)
