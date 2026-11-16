"""
802.11 frame classification.

Takes a flat list of scapy packets and sorts them into typed buckets.
No feature extraction or security analysis is performed here.

Frame types captured
--------------------
Beacon        — type=0, subtype=8
Probe Request — type=0, subtype=4
Deauth        — type=0, subtype=12
Disassociation— type=0, subtype=10  (treated as deauth-equivalent for counting)
EAPOL         — type=2 (Data), scapy-decoded or detected via LLC/SNAP header
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11ProbeReq
from scapy.layers.eap import EAPOL
from scapy.packet import Packet

# Dot11Disas exists in scapy 2.5+; guard import for safety.
try:
    from scapy.layers.dot11 import Dot11Disas as _Dot11Disas  # type: ignore[attr-defined]
    _HAVE_DISAS = True
except ImportError:
    _HAVE_DISAS = False

# LLC/SNAP magic bytes that precede EAPOL in an 802.11 data frame payload.
_LLC_SNAP_EAPOL: bytes = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"


@dataclass
class ParsedFrames:
    """
    Typed frame buckets produced by :func:`parse_frames`.

    Each list holds references to the original scapy packet objects
    (no deep copies).  The originating packet list is not modified.
    """

    beacon_frames: List[Packet] = field(default_factory=list)
    """Dot11Beacon management frames."""

    probe_requests: List[Packet] = field(default_factory=list)
    """Dot11ProbeReq management frames."""

    deauth_frames: List[Packet] = field(default_factory=list)
    """Deauthentication (subtype 12) and Disassociation (subtype 10) frames."""

    eapol_frames: List[Packet] = field(default_factory=list)
    """
    Frames carrying EAPOL payloads.
    Includes both scapy-decoded EAPOL layers and data frames whose raw
    payload begins with the LLC/SNAP EAPOL header (0xAA AA 03 00 00 00 88 8E).
    """

    other_frames: List[Packet] = field(default_factory=list)
    """All packets that did not match any of the above categories."""

    @property
    def total_frames(self) -> int:
        """Sum of all frames across all buckets."""
        return (
            len(self.beacon_frames)
            + len(self.probe_requests)
            + len(self.deauth_frames)
            + len(self.eapol_frames)
            + len(self.other_frames)
        )


def parse_frames(packets: List[Packet]) -> ParsedFrames:
    """
    Classify a list of scapy packets into typed 802.11 frame buckets.

    Parameters
    ----------
    packets : list[Packet]
        Raw scapy packet list, typically from
        :func:`wsa.ingestion.pcap_reader.load_pcap`.

    Returns
    -------
    ParsedFrames
        Populated bucket object.  Never raises; malformed individual frames
        are placed in ``other_frames``.
    """
    result = ParsedFrames()

    for pkt in packets:
        try:
            _classify(pkt, result)
        except Exception:
            # A single malformed packet must not abort the whole parse.
            result.other_frames.append(pkt)

    return result


# ---------------------------------------------------------------------------
# Internal classification logic
# ---------------------------------------------------------------------------

def _classify(pkt: Packet, result: ParsedFrames) -> None:
    """Place one packet into the correct bucket of *result*."""

    # Packets without a Dot11 layer are not 802.11 frames.
    if not pkt.haslayer(Dot11):
        result.other_frames.append(pkt)
        return

    # ---- Management frames ------------------------------------------------
    if pkt.haslayer(Dot11Beacon):
        result.beacon_frames.append(pkt)
        return

    if pkt.haslayer(Dot11ProbeReq):
        result.probe_requests.append(pkt)
        return

    if _is_deauth_or_disassoc(pkt):
        result.deauth_frames.append(pkt)
        return

    # ---- EAPOL (data frames) ---------------------------------------------
    # Scapy 2.8 fully dissects EAPOL-Key; also detect via raw LLC/SNAP header
    # for cases where scapy keeps the payload as Raw.
    if pkt.haslayer(EAPOL) or _raw_payload_is_eapol(pkt):
        result.eapol_frames.append(pkt)
        return

    result.other_frames.append(pkt)


def _is_deauth_or_disassoc(pkt: Packet) -> bool:
    """
    Return True for deauthentication (subtype 12) and disassociation
    (subtype 10) management frames.
    """
    if pkt.haslayer(Dot11Deauth):
        return True
    if _HAVE_DISAS and pkt.haslayer(_Dot11Disas):
        return True
    # Fallback: check subtype numerically (handles any scapy version).
    d = pkt[Dot11]
    return d.type == 0 and d.subtype in (10, 12)


def _raw_payload_is_eapol(pkt: Packet) -> bool:
    """
    Heuristic: the innermost Raw layer starts with the LLC/SNAP EAPOL header.
    Used when scapy leaves the data frame payload undissected.
    """
    from scapy.packet import Raw
    if not pkt.haslayer(Raw):
        return False
    raw = bytes(pkt[Raw].load)
    return len(raw) >= len(_LLC_SNAP_EAPOL) and raw[: len(_LLC_SNAP_EAPOL)] == _LLC_SNAP_EAPOL
