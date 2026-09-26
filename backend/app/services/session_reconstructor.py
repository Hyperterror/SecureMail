"""
Session reconstructor — groups raw packets into logical email sessions.

Uses the TCP stream index (from tshark) or the 5-tuple as a session key.
Detects transport mode (Plaintext / STARTTLS / Implicit TLS) and protocol.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import (
    EMAIL_PORTS,
    IMPLICIT_TLS_PORTS,
    Protocol,
    TransportMode,
)


def reconstruct_sessions(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Group packets into logical email sessions.

    Each session is keyed by TCP stream index (preferred) or 5-tuple.

    Returns:
        List of session dicts with keys:
        - packets: list of packet dicts
        - protocol: Protocol enum value
        - transport_mode: TransportMode enum value
        - source_ip, source_port, dest_ip, dest_port
        - starttls_detected: bool
    """
    session_map: dict[str, dict[str, Any]] = {}

    for pkt in packets:
        # Use TCP stream index if available (more reliable than 5-tuple)
        if "tcp_stream" in pkt:
            key = f"stream-{pkt['tcp_stream']}"
        else:
            # Fallback: canonical 5-tuple (sorted so both directions map to same session)
            endpoints = sorted([
                (pkt["src_ip"], pkt["src_port"]),
                (pkt["dst_ip"], pkt["dst_port"]),
            ])
            key = f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}"

        if key not in session_map:
            # Determine protocol from port
            protocol = _detect_protocol(pkt)

            # Determine initial transport mode from port
            dst_port = pkt["dst_port"]
            src_port = pkt["src_port"]
            email_port = dst_port if dst_port in EMAIL_PORTS else src_port

            if email_port in IMPLICIT_TLS_PORTS:
                transport = TransportMode.IMPLICIT_TLS
            else:
                transport = TransportMode.PLAINTEXT

            # Determine client/server direction
            if pkt["dst_port"] in EMAIL_PORTS:
                client_ip, client_port = pkt["src_ip"], pkt["src_port"]
                server_ip, server_port = pkt["dst_ip"], pkt["dst_port"]
            else:
                client_ip, client_port = pkt["dst_ip"], pkt["dst_port"]
                server_ip, server_port = pkt["src_ip"], pkt["src_port"]

            session_map[key] = {
                "packets": [],
                "protocol": protocol,
                "transport_mode": transport,
                "source_ip": client_ip,
                "source_port": client_port,
                "dest_ip": server_ip,
                "dest_port": server_port,
                "starttls_detected": False,
                "has_tls": False,
            }

        session = session_map[key]
        session["packets"].append(pkt)

        # Update session properties based on packet content
        if pkt.get("starttls_detected"):
            session["starttls_detected"] = True
            session["transport_mode"] = TransportMode.STARTTLS

        if pkt.get("has_tls"):
            session["has_tls"] = True
            # If TLS is present on a non-implicit port, it's STARTTLS
            if session["transport_mode"] == TransportMode.PLAINTEXT:
                session["transport_mode"] = TransportMode.STARTTLS

    # Post-process: if no TLS was seen and not implicit, it's plaintext
    for session in session_map.values():
        if not session["has_tls"] and session["transport_mode"] != TransportMode.IMPLICIT_TLS:
            session["transport_mode"] = TransportMode.PLAINTEXT

    return list(session_map.values())


def _detect_protocol(pkt: dict[str, Any]) -> Protocol:
    """Detect email protocol from packet ports."""
    for port_key in ("dst_port", "src_port"):
        port = pkt.get(port_key, 0)
        proto = EMAIL_PORTS.get(port)
        if proto:
            return proto
    return Protocol.UNKNOWN
