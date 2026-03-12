"""FastAPI Backend for MetaForensicAI.

Exposes the 15-point forensic pipeline as a RESTful service.
"""
import os
import shutil
import uuid
import importlib
from typing import Any, Optional
from pathlib import Path
from datetime import datetime

try:
    fastapi_module = importlib.import_module("fastapi")
    pydantic_module = importlib.import_module("pydantic")
except ImportError as exc:
    raise RuntimeError(
        "FastAPI API dependencies are missing. Install with: pip install fastapi pydantic"
    ) from exc

FastAPI = getattr(fastapi_module, "FastAPI")
File = getattr(fastapi_module, "File")
UploadFile = getattr(fastapi_module, "UploadFile")
HTTPException = getattr(fastapi_module, "HTTPException")
BackgroundTasks = getattr(fastapi_module, "BackgroundTasks")
BaseModel = getattr(pydantic_module, "BaseModel")

from ..main import MetaForensicAI

app = FastAPI(
    title="MetaForensicAI Enterprise API",
    description="Advanced Explainable AI Digital Forensics Analysis Engine",
    version="1.0.0"
)

# Initialize the forensic engine
engine = MetaForensicAI()

# Directories for API usage
UPLOAD_DIR = Path("api_uploads")
REPORT_DIR = Path("results/reports")
UPLOAD_DIR.mkdir(exist_ok=True)

class AnalysisResponse(BaseModel):
    case_id: str
    filename: str
    status: str
    risk_score: float
    risk_level: str
    summary: str
    analysis_timestamp: str

@app.get("/")
async def root():
    return {
        "system": "MetaForensicAI",
        "version": "1.0.0",
        "status": "operational",
        "capabilities": [
            "15-Point Forensic Pipeline",
            "Error Level Analysis (ELA)",
            "Quantization Table Auditing",
            "Predictive Bayesian Risk Scoring",
            "Explainable AI (XAI) Narratives"
        ]
    }

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_image(
    background_tasks: Any,
    file: Any = File(...),
    case_id: Optional[str] = None
):
    """
    Perform 15-point forensic analysis on an uploaded image.
    """
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image.")

    # Generate Case ID if not provided
    if not case_id:
        case_id = f"CASE_{uuid.uuid4().hex[:8].upper()}"

    # Save uploaded file
    file_path = UPLOAD_DIR / f"{case_id}_{file.filename}"
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        # Perform analysis
        results = engine.analyze_image(str(file_path), case_info={"case_id": case_id})
        
        # Generate reports in background
        background_tasks.add_task(
            engine.generate_reports, 
            output_dir=str(REPORT_DIR / case_id),
            formats=['json', 'html', 'pdf']
        )

        risk = results.get('risk_assessment', {})
        
        return AnalysisResponse(
            case_id=case_id,
            filename=file.filename,
            status="completed",
            risk_score=risk.get('risk_score', 0.0),
            risk_level=risk.get('level', "UNKNOWN"),
            summary=risk.get('findings_summary', "Analysis complete."),
            analysis_timestamp=results.get('analysis_timestamp', datetime.now().isoformat())
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {str(e)}")

@app.get("/cases/{case_id}")
async def get_case_results(case_id: str):
    """
    Retrieve results for a specific case.
    """
    report_path = REPORT_DIR / case_id / "summary.json" # Hypothetical structured path
    # For now, we'll check if the directory exists
    if not (REPORT_DIR / case_id).exists():
        raise HTTPException(status_code=404, detail="Case not found or reports not yet generated.")
    
    return {"case_id": case_id, "report_directory": str((REPORT_DIR / case_id).absolute())}

@app.get("/health")
async def health():
    return engine.get_system_info()

if __name__ == "__main__":
    try:
        uvicorn = importlib.import_module("uvicorn")
    except ImportError as exc:
        raise RuntimeError("Uvicorn is required to run the API server. Install with: pip install uvicorn") from exc
    uvicorn.run(app, host="0.0.0.0", port=8000)
