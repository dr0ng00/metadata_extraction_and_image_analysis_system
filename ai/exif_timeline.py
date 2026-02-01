from datetime import datetime

class ExIFTimelineAnalyzer:

    def analyze(self, metadata):
        timestamps = {}

        for k in ["DateTimeOriginal", "CreateDate", "ModifyDate"]:
            if k in metadata:
                try:
                    timestamps[k] = datetime.strptime(
                        metadata[k], "%Y:%m:%d %H:%M:%S"
                    )
                except:
                    pass

        ordered = sorted(timestamps.items(), key=lambda x: x[1])

        anomalies = []
        if "ModifyDate" in timestamps and "DateTimeOriginal" in timestamps:
            if timestamps["ModifyDate"] < timestamps["DateTimeOriginal"]:
                anomalies.append("Modification before capture")

        return {
            "timeline": {k: v.isoformat() for k, v in ordered},
            "anomalies_detected": bool(anomalies),
            "anomalies": anomalies
        }
