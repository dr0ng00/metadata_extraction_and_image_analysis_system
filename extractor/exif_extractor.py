import subprocess
import json
import os
import shutil


def extract_metadata_from_path(image_path: str) -> dict:
    """
    Extract EXIF metadata using ExifTool WITHOUT saving anything to disk.
    """

    image_path = os.path.abspath(image_path)

    if not shutil.which("exiftool"):
        return {"_error": "ExifTool not installed or not in PATH"}

    if not os.path.exists(image_path):
        return {"_error": f"Image not found: {image_path}"}

    command = [
        "exiftool",
        "-j",   # JSON output
        "-n",   # Numeric values
        image_path
    ]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=True
        )

        if not result.stdout.strip():
            return {}

        return json.loads(result.stdout)[0]

    except subprocess.TimeoutExpired:
        return {"_error": "ExifTool timeout"}

    except subprocess.CalledProcessError as e:
        return {"_error": e.stderr}

    except json.JSONDecodeError:
        return {"_error": "Invalid JSON from ExifTool"}

    except Exception as e:
        return {"_error": str(e)}


def extract_metadata_from_bytes(image_bytes: bytes) -> dict:
    """
    Extract EXIF metadata from image bytes (NO FILE STORAGE).
    Uses ExifTool via stdin.
    """

    if not shutil.which("exiftool"):
        return {"_error": "ExifTool not installed or not in PATH"}

    try:
        process = subprocess.run(
            ["exiftool", "-j", "-n", "-"],
            input=image_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=True
        )

        if not process.stdout:
            return {}

        return json.loads(process.stdout)[0]

    except subprocess.TimeoutExpired:
        return {"_error": "ExifTool timeout (stdin)"}

    except subprocess.CalledProcessError as e:
        return {"_error": e.stderr.decode(errors="ignore")}

    except json.JSONDecodeError:
        return {"_error": "Invalid JSON from ExifTool"}

    except Exception as e:
        return {"_error": str(e)}
# Backward-compatible alias
def extract_metadata(image_path: str) -> dict:
    return extract_metadata_from_path(image_path)
