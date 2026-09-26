"""
Export API router — JSON and HTML report downloads.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.services.export_service import export_html, export_json

router = APIRouter(prefix="/api", tags=["export"])


@router.get("/analysis/{analysis_id}/export/json")
async def download_json(analysis_id: str) -> Response:
    """Download analysis result as JSON."""
    from app.routers.analysis import _analyses

    if analysis_id not in _analyses:
        raise HTTPException(404, f"Analysis {analysis_id} not found.")

    result = _analyses[analysis_id]
    content = export_json(result)

    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="securemailscope_{analysis_id}.json"',
        },
    )


@router.get("/analysis/{analysis_id}/export/html")
async def download_html(analysis_id: str) -> Response:
    """Download analysis result as self-contained HTML report."""
    from app.routers.analysis import _analyses

    if analysis_id not in _analyses:
        raise HTTPException(404, f"Analysis {analysis_id} not found.")

    result = _analyses[analysis_id]
    content = export_html(result)

    return Response(
        content=content,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="securemailscope_{analysis_id}.html"',
        },
    )
