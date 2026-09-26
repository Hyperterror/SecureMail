"""
Analysis API router — upload, analyze (SSE), and demo endpoints.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from app.models.schemas import AnalysisResult, UploadResponse
from app.services.demo_generator import generate_demo_data

router = APIRouter(prefix="/api", tags=["analysis"])

# In-memory storage for analysis results (Phase 1 — no DB)
_analyses: dict[str, AnalysisResult] = {}
_uploads: dict[str, dict[str, Any]] = {}

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Allowed PCAP magic bytes
_PCAP_MAGIC = [
    b"\xd4\xc3\xb2\xa1",  # pcap little-endian
    b"\xa1\xb2\xc3\xd4",  # pcap big-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng
]
_MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB


@router.post("/upload", response_model=UploadResponse)
async def upload_pcap(file: UploadFile) -> UploadResponse:
    """
    Upload a PCAP file for analysis.

    Validates file extension and magic bytes, saves to disk,
    returns an analysis_id for subsequent analysis.
    """
    if not file.filename:
        raise HTTPException(400, "No filename provided")

    # Validate extension
    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng"):
        raise HTTPException(
            400,
            f"Unsupported file type: {suffix}. Only .pcap and .pcapng are accepted.",
        )

    # Read first bytes to validate magic number
    header = await file.read(4)
    if header not in _PCAP_MAGIC:
        raise HTTPException(400, "File does not appear to be a valid PCAP file.")
    await file.seek(0)

    # Generate analysis ID and save file
    analysis_id = str(uuid.uuid4())[:8]
    save_path = UPLOAD_DIR / f"{analysis_id}{suffix}"

    file_size = 0
    with open(save_path, "wb") as out:
        while chunk := await file.read(8192):
            file_size += len(chunk)
            if file_size > _MAX_FILE_SIZE:
                save_path.unlink(missing_ok=True)
                raise HTTPException(413, "File too large. Maximum size is 500 MB.")
            out.write(chunk)

    _uploads[analysis_id] = {
        "filepath": str(save_path),
        "filename": file.filename,
        "file_size": file_size,
    }

    return UploadResponse(
        analysis_id=analysis_id,
        filename=file.filename,
        file_size_bytes=file_size,
    )


@router.get("/analyze/{analysis_id}")
async def analyze_pcap(analysis_id: str) -> StreamingResponse:
    """
    Analyze a previously uploaded PCAP file.

    Returns Server-Sent Events (SSE) streaming progress updates,
    with the final event containing the complete analysis result.
    """
    if analysis_id not in _uploads:
        raise HTTPException(404, f"Analysis {analysis_id} not found. Upload a file first.")

    upload = _uploads[analysis_id]

    async def event_stream():
        try:
            # Stage 1: Parsing PCAP
            yield _sse_event({"stage": "parsing", "progress": 10, "message": "Parsing PCAP file..."})
            await asyncio.sleep(0.3)

            from app.services.pcap_parser import parse_pcap
            parse_result = await parse_pcap(upload["filepath"])

            yield _sse_event({"stage": "parsing", "progress": 30, "message": f"Parsed {parse_result['total_scanned']} packets"})
            await asyncio.sleep(0.2)

            # Stage 2: Detecting protocols
            yield _sse_event({"stage": "detecting_protocols", "progress": 40, "message": "Detecting email protocols..."})
            await asyncio.sleep(0.2)

            # Stage 3: Reconstructing sessions
            yield _sse_event({"stage": "reconstructing", "progress": 50, "message": "Reconstructing sessions..."})
            from app.services.session_reconstructor import reconstruct_sessions
            raw_sessions = reconstruct_sessions(parse_result["packets"])
            await asyncio.sleep(0.2)

            # Stage 4: Extracting TLS
            yield _sse_event({"stage": "extracting_tls", "progress": 60, "message": "Extracting TLS information..."})
            from app.services.tls_extractor import extract_sessions
            sessions = extract_sessions(raw_sessions)
            await asyncio.sleep(0.2)

            # Stage 5: Analyzing certificates
            yield _sse_event({"stage": "analyzing_certs", "progress": 75, "message": "Analyzing certificates..."})
            await asyncio.sleep(0.2)

            # Stage 6: Running rule engine
            yield _sse_event({"stage": "rule_engine", "progress": 80, "message": "Evaluating security rules..."})
            from app.services.rule_engine import evaluate
            for session in sessions:
                rule_score, findings = evaluate(session)
                session.rule_score = rule_score
                session.findings = findings
            await asyncio.sleep(0.2)

            # Stage 7: ML anomaly detection
            yield _sse_event({"stage": "ml_detection", "progress": 90, "message": "Running anomaly detection..."})
            from app.services.feature_engine import extract_features_batch
            from app.services.ml_engine import AnomalyDetector
            from app.services.risk_aggregator import aggregate_risk, compute_security_posture

            features = extract_features_batch(sessions)
            detector = AnomalyDetector()
            anomaly_scores = detector.fit_and_predict(features)

            for session, ml_score in zip(sessions, anomaly_scores):
                session.ml_anomaly_score = round(float(ml_score), 3)
                combined, risk_level, confidence = aggregate_risk(
                    session.rule_score, session.ml_anomaly_score,
                )
                session.risk_level = risk_level
                session.confidence = confidence
            await asyncio.sleep(0.1)

            # Stage 8: Build result
            yield _sse_event({"stage": "finalizing", "progress": 95, "message": "Building analysis result..."})

            from datetime import datetime, timezone
            tls_dist = {}
            proto_dist = {}
            transport_dist = {}
            risk_dist = {}
            for s in sessions:
                tls_dist[s.tls_version.value] = tls_dist.get(s.tls_version.value, 0) + 1
                proto_dist[s.protocol.value] = proto_dist.get(s.protocol.value, 0) + 1
                transport_dist[s.transport_mode.value] = transport_dist.get(s.transport_mode.value, 0) + 1
                risk_dist[s.risk_level.value] = risk_dist.get(s.risk_level.value, 0) + 1

            total_findings = sum(len(s.findings) for s in sessions)

            result = AnalysisResult(
                analysis_id=analysis_id,
                filename=upload["filename"],
                file_size_bytes=upload["file_size"],
                total_packets=parse_result["total_scanned"],
                total_sessions=len(sessions),
                total_findings=total_findings,
                security_posture=compute_security_posture(sessions),
                sessions=sessions,
                tls_version_distribution=tls_dist,
                protocol_distribution=proto_dist,
                transport_mode_distribution=transport_dist,
                risk_distribution=risk_dist,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

            _analyses[analysis_id] = result

            yield _sse_event({
                "stage": "complete",
                "progress": 100,
                "message": "Analysis complete",
                "result": json.loads(result.model_dump_json()),
            })

        except ImportError as e:
            yield _sse_event({
                "stage": "error",
                "progress": 0,
                "message": str(e),
            })
        except Exception as e:
            yield _sse_event({
                "stage": "error",
                "progress": 0,
                "message": f"Analysis failed: {str(e)}",
            })

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/demo")
async def demo_analysis() -> AnalysisResult:
    """
    Generate demo analysis data.

    Returns a complete AnalysisResult with 37 synthetic sessions,
    fully scored by both rule engine and ML anomaly detection.
    No PCAP file or tshark needed.
    """
    result = generate_demo_data()
    _analyses[result.analysis_id] = result
    return result


@router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str) -> AnalysisResult:
    """Retrieve a completed analysis result."""
    if analysis_id not in _analyses:
        raise HTTPException(404, f"Analysis {analysis_id} not found.")
    return _analyses[analysis_id]


def _sse_event(data: dict) -> str:
    """Format a dict as an SSE event string."""
    return f"data: {json.dumps(data)}\n\n"
