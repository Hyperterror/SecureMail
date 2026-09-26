"""
PCAP parser using PyShark (tshark wrapper).

Extracts raw packet information from PCAP/PCAPNG files, filtering for
email-related traffic (SMTP, IMAP, POP3) on standard ports.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Coroutine

from app.models.enums import EMAIL_PORTS, Protocol


async def parse_pcap(
    filepath: str,
    progress_callback: Callable[[str, int], Coroutine] | None = None,
) -> dict[str, Any]:
    """
    Parse a PCAP file and extract email-related packet data.

    Args:
        filepath: Path to the .pcap or .pcapng file.
        progress_callback: Optional async callback(stage, progress_pct).

    Returns:
        {"packets": [...], "total_scanned": int}

    Raises:
        ImportError: If pyshark/tshark is not installed.
        FileNotFoundError: If the PCAP file doesn't exist.
    """
    if not Path(filepath).exists():
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    try:
        import pyshark
    except ImportError:
        raise ImportError(
            "pyshark is not installed. Install it with: pip install pyshark\n"
            "Also ensure tshark (Wireshark CLI) is installed and in PATH."
        )

    # Open capture filtering for email ports
    email_port_filter = " or ".join(
        f"tcp.port == {port}" for port in EMAIL_PORTS
    )
    cap = pyshark.FileCapture(
        filepath,
        display_filter=email_port_filter,
        keep_packets=False,
    )

    packets: list[dict[str, Any]] = []
    total_scanned = 0

    try:
        for pkt in cap:
            total_scanned += 1
            packet_info = _extract_packet_info(pkt)
            if packet_info:
                packets.append(packet_info)

            if progress_callback and total_scanned % 200 == 0:
                await progress_callback("parsing", min(total_scanned, 95))
    finally:
        cap.close()

    return {
        "packets": packets,
        "total_scanned": total_scanned,
    }


def _extract_packet_info(pkt: Any) -> dict[str, Any] | None:
    """Extract relevant fields from a single packet."""
    try:
        if not hasattr(pkt, "tcp"):
            return None

        info: dict[str, Any] = {
            "frame_number": int(pkt.number),
            "timestamp": float(pkt.sniff_timestamp),
            "src_ip": str(pkt.ip.src) if hasattr(pkt, "ip") else "0.0.0.0",
            "dst_ip": str(pkt.ip.dst) if hasattr(pkt, "ip") else "0.0.0.0",
            "src_port": int(pkt.tcp.srcport),
            "dst_port": int(pkt.tcp.dstport),
            "tcp_stream": int(pkt.tcp.stream) if hasattr(pkt.tcp, "stream") else 0,
            "tcp_len": int(pkt.tcp.len) if hasattr(pkt.tcp, "len") else 0,
            "tcp_flags": str(pkt.tcp.flags) if hasattr(pkt.tcp, "flags") else "",
            "is_retransmission": hasattr(pkt.tcp, "analysis_retransmission"),
        }

        # Detect protocol from port
        src_proto = EMAIL_PORTS.get(info["src_port"])
        dst_proto = EMAIL_PORTS.get(info["dst_port"])
        info["protocol"] = (dst_proto or src_proto or Protocol.UNKNOWN).value

        # Extract TLS layer info if present
        if hasattr(pkt, "tls"):
            info["has_tls"] = True
            tls = pkt.tls

            if hasattr(tls, "handshake_type"):
                info["tls_handshake_type"] = str(tls.handshake_type)

            if hasattr(tls, "handshake_version"):
                info["tls_version_raw"] = str(tls.handshake_version)

            if hasattr(tls, "handshake_ciphersuite"):
                info["tls_cipher_suite"] = str(tls.handshake_ciphersuite)

            if hasattr(tls, "handshake_extensions_supported_version"):
                info["tls_supported_version"] = str(tls.handshake_extensions_supported_version)

            # Certificate fields
            if hasattr(tls, "x509sat_printableString"):
                info["cert_subject"] = str(tls.x509sat_printableString)
            if hasattr(tls, "x509ce_dNSName"):
                info["cert_san"] = str(tls.x509ce_dNSName)
            if hasattr(tls, "x509af_utcTime"):
                info["cert_time"] = str(tls.x509af_utcTime)
            if hasattr(tls, "x509ce_subjectKeyIdentifier"):
                info["cert_key_id"] = str(tls.x509ce_subjectKeyIdentifier)
        else:
            info["has_tls"] = False

        # Extract SMTP/IMAP/POP3 commands for STARTTLS detection
        for layer_name in ("smtp", "imap", "pop"):
            if hasattr(pkt, layer_name):
                layer = getattr(pkt, layer_name)
                info[f"{layer_name}_data"] = str(layer)
                # Check for STARTTLS commands
                layer_str = str(layer).upper()
                if "STARTTLS" in layer_str or "STLS" in layer_str:
                    info["starttls_detected"] = True

        return info

    except Exception:
        return None
