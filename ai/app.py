from fastapi import FastAPI, UploadFile, Query
import cv2
import numpy as np

from ai.inference import ForensicInferenceEngine
from extractor.exif_extractor import extract_metadata_from_bytes

app = FastAPI()
engine = ForensicInferenceEngine()


@app.post("/analyze")
async def analyze_image(
    file: UploadFile,
    query: str = Query(..., description="User request, e.g. 'count humans', 'get location'")
):
    # Read image bytes (NO storage)
    content = await file.read()

    # Decode image
    image = cv2.imdecode(np.frombuffer(content, np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return {"error": "Invalid image"}

    # Extract EXIF metadata from memory
    metadata = extract_metadata_from_bytes(content)

    # Run AI inference
    response = engine.run(
        image=image,
        metadata=metadata,
        user_request=query
    )

    return response
