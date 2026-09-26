"""
Sessions API router — list and filter sessions, get session details.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.models.enums import Protocol, RiskLevel, TLSVersion, TransportMode
from app.models.schemas import SessionInfo

router = APIRouter(prefix="/api", tags=["sessions"])


@router.get("/analysis/{analysis_id}/sessions", response_model=list[SessionInfo])
async def list_sessions(
    analysis_id: str,
    protocol: Protocol | None = Query(None, description="Filter by protocol"),
    tls_version: TLSVersion | None = Query(None, description="Filter by TLS version"),
    transport: TransportMode | None = Query(None, description="Filter by transport mode"),
    risk: RiskLevel | None = Query(None, description="Filter by risk level"),
    forward_secrecy: bool | None = Query(None, description="Filter by forward secrecy"),
    search: str | None = Query(None, description="Search by IP, host, or session ID"),
) -> list[SessionInfo]:
    """List sessions with optional filtering."""
    from app.routers.analysis import _analyses

    if analysis_id not in _analyses:
        raise HTTPException(404, f"Analysis {analysis_id} not found.")

    sessions = _analyses[analysis_id].sessions

    # Apply filters
    if protocol is not None:
        sessions = [s for s in sessions if s.protocol == protocol]
    if tls_version is not None:
        sessions = [s for s in sessions if s.tls_version == tls_version]
    if transport is not None:
        sessions = [s for s in sessions if s.transport_mode == transport]
    if risk is not None:
        sessions = [s for s in sessions if s.risk_level == risk]
    if forward_secrecy is not None:
        sessions = [s for s in sessions if s.forward_secrecy == forward_secrecy]
    if search:
        q = search.lower()
        sessions = [
            s for s in sessions
            if q in s.source_ip.lower()
            or q in s.dest_ip.lower()
            or q in s.session_id.lower()
            or (s.cipher_suite and q in s.cipher_suite.lower())
            or (s.certificate and s.certificate.subject and q in s.certificate.subject.lower())
        ]

    return sessions


@router.get("/analysis/{analysis_id}/sessions/{session_id}", response_model=SessionInfo)
async def get_session(analysis_id: str, session_id: str) -> SessionInfo:
    """Get detailed information for a specific session."""
    from app.routers.analysis import _analyses

    if analysis_id not in _analyses:
        raise HTTPException(404, f"Analysis {analysis_id} not found.")

    for session in _analyses[analysis_id].sessions:
        if session.session_id == session_id:
            return session

    raise HTTPException(404, f"Session {session_id} not found.")
