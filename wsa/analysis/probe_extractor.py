"""
Probe-request frame analysis.

Extracts directed SSID names and client MAC addresses from
Dot11ProbeReq frames.  Broadcast probes (empty SSID) are excluded
from the SSID set but the client MAC is still recorded.
"""
from __future__ import annotations

from typing import List, Optional, Set

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq
from scapy.packet import Packet


def extract_probed_ssids(probe_requests: List[Packet]) -> Set[str]:
    """
    Return the set of network names in directed probe requests.

    Broadcast / wildcard probes (SSID IE absent or empty) are excluded.
    Non-UTF-8 bytes in the SSID are replaced with the Unicode replacement
    character (U+FFFD) rather than raising an exception.

    Parameters
    ----------
    probe_requests : list[Packet]
        Packets classified as probe requests by the frame parser.

    Returns
    -------
    set[str]
        Unique SSID strings.  Empty set if all probes were broadcast
        or if *probe_requests* is empty.
    """
    ssids: Set[str] = set()
    for pkt in probe_requests:
        ssid = _probe_ssid(pkt)
        if ssid is not None:
            ssids.add(ssid)
    return ssids


def extract_client_macs(probe_requests: List[Packet]) -> Set[str]:
    """
    Return the set of client MAC addresses seen in probe requests.

    The transmitter address (addr2) is used as the client identifier.
    Broadcast and all-zero addresses are excluded.

    Parameters
    ----------
    probe_requests : list[Packet]
        Packets classified as probe requests by the frame parser.

    Returns
    -------
    set[str]
        Unique lower-case colon-separated MAC address strings.
    """
    macs: Set[str] = set()
    for pkt in probe_requests:
        mac = _safe_addr(pkt, "addr2")
        if mac:
            macs.add(mac)
    return macs


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _probe_ssid(pkt: Packet) -> Optional[str]:
    """
    Extract the SSID string from a probe request, or ``None`` for
    broadcast probes (empty or absent SSID IE).
    """
    if not pkt.haslayer(Dot11ProbeReq):
        return None

    # Walk IEs from the first layer after Dot11ProbeReq.
    layer = pkt[Dot11ProbeReq].payload
    while layer and layer.name != "NoPayload":
        if getattr(layer, "ID", -1) == 0:  # SSID IE
            raw = bytes(layer.info) if layer.info else b""
            # Exclude empty SSIDs and null-padded SSIDs (broadcast probes).
            if raw and raw.strip(b"\x00"):
                return raw.decode("utf-8", errors="replace")
            return None  # broadcast probe
        layer = layer.payload

    return None  # SSID IE not found


def _safe_addr(pkt: Packet, addr_field: str) -> Optional[str]:
    """Return a normalised MAC address string, or ``None`` for invalid values."""
    _INVALID = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
    if not pkt.haslayer(Dot11):
        return None
    val = getattr(pkt[Dot11], addr_field, None)
    if not val:
        return None
    val = val.lower()
    return None if val in _INVALID else val
