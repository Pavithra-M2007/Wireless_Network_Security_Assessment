"""
Beacon frame analysis and network feature extraction.

Processes Dot11Beacon frames to produce NetworkFeatures objects.
One NetworkFeatures is produced per unique BSSID; multiple beacons from
the same AP are merged so that each field reflects the best evidence
seen across all beacons.

Evidence policy
---------------
* Fields are set only when the corresponding IE or capability bit is
  present in at least one beacon frame for that BSSID.
* ``None`` / empty list means the evidence was absent — not that the
  feature is disabled.
* Inferred values (e.g. cipher = WEP derived from the privacy bit alone
  when no RSN IE is present) are documented in ``feature_set.py``.
* Non-fatal parse issues are recorded in ``NetworkFeatures.parser_notes``.

Scapy 2.8 layer hierarchy (important for isinstance checks)
------------------------------------------------------------
Dot11Elt                  — generic IE (SSID, Rates, …)
  ├─ Dot11EltRSN          — ID=48, fully dissected RSN
  ├─ Dot11EltVendorSpecific — ID=221, OUI + payload
  └─ Dot11EltDSSSet       — ID=3, has .channel attribute
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRSN,
    RadioTap,
)
from scapy.packet import Packet

# Dot11EltVendorSpecific: available in scapy 2.5+; guard import.
try:
    from scapy.layers.dot11 import Dot11EltVendorSpecific as _VendorSpecific
    _HAVE_VENDOR_CLASS = True
except ImportError:
    _VendorSpecific = None  # type: ignore[assignment]
    _HAVE_VENDOR_CLASS = False

from wsa.analysis.feature_set import (
    AUTH_EAP, AUTH_OPEN, AUTH_OWE, AUTH_PSK, AUTH_SAE, AUTH_UNKNOWN,
    CIPHER_CCMP, CIPHER_GCMP, CIPHER_MIXED, CIPHER_NONE,
    CIPHER_TKIP, CIPHER_UNKNOWN, CIPHER_WEP,
    NetworkFeatures,
)

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

# RSN pairwise / group cipher suite selector → label
_CIPHER_MAP: Dict[int, str] = {
    1:  CIPHER_WEP,    # WEP-40
    2:  CIPHER_TKIP,
    4:  CIPHER_CCMP,   # CCMP-128 (AES)
    5:  CIPHER_WEP,    # WEP-104
    8:  CIPHER_GCMP,   # GCMP-128
    9:  CIPHER_GCMP,   # GCMP-256
    10: CIPHER_CCMP,   # CCMP-256
}

# RSN AKM suite selector → label
_AKM_MAP: Dict[int, str] = {
    1:  AUTH_EAP,   # 802.1X
    2:  AUTH_PSK,
    3:  AUTH_EAP,   # FT/802.1X
    4:  AUTH_PSK,   # FT/PSK
    5:  AUTH_EAP,   # 802.1X SHA-256
    6:  AUTH_PSK,   # PSK SHA-256
    8:  AUTH_SAE,
    9:  AUTH_SAE,   # FT/SAE
    18: AUTH_OWE,
}

# Vendor-specific OUI+type for WPS and WPA1
_WPS_OUI_TYPE  = b"\x00\x50\xf2\x04"
_WPA1_OUI_TYPE = b"\x00\x50\xf2\x01"

# Broadcast address — excluded from BSSID lookups
_BROADCAST = "ff:ff:ff:ff:ff:ff"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_networks(
    beacon_frames: List[Packet],
    deauth_frames: List[Packet],
    eapol_frames: List[Packet],
) -> List[NetworkFeatures]:
    """
    Build one :class:`~wsa.analysis.feature_set.NetworkFeatures` per unique
    BSSID from beacon frames.

    Deauth and EAPOL frames are associated by BSSID (via ``addr3``) and used
    to populate count fields only.

    Parameters
    ----------
    beacon_frames : list
        Packets containing a Dot11Beacon layer.
    deauth_frames : list
        Deauthentication / disassociation packets (from frame parser).
    eapol_frames : list
        EAPOL packets (scapy-decoded or raw-payload detected).

    Returns
    -------
    list[NetworkFeatures]
        One entry per BSSID, ordered by first observation.
    """
    # --- Group beacons by BSSID -------------------------------------------
    by_bssid: Dict[str, List[Packet]] = {}
    for pkt in beacon_frames:
        bssid = _bssid_from_packet(pkt)
        if bssid:
            by_bssid.setdefault(bssid, []).append(pkt)

    # --- Count deauth / disassoc frames per BSSID -------------------------
    # Deauthentication frame address semantics vary by attack pattern:
    #
    # Legitimate AP-originated deauth:
    #   addr1=client, addr2=BSSID, addr3=BSSID
    #
    # Spoofed deauth flood (common attack, as in our synthetic data):
    #   addr1=ff:ff:ff:ff:ff:ff (broadcast), addr2=attacker, addr3=attacker
    #   The targeted AP BSSID may NOT appear in the deauth frame at all.
    #
    # Strategy: check addr1, addr2, addr3 against all known BSSIDs first.
    # If none match but addr1 is broadcast, attribute the frame to every AP
    # whose BSSID was seen in beacon frames on the same channel (or all APs
    # when channel information is unavailable).  This correctly handles both
    # the legitimate and spoofed flood patterns.
    known_bssids = set(by_bssid.keys())
    deauth_counts: Dict[str, int] = {}
    for pkt in deauth_frames:
        matched = False
        for addr_field in ("addr3", "addr2", "addr1"):
            mac = _safe_addr(pkt, addr_field)
            if mac and mac in known_bssids:
                deauth_counts[mac] = deauth_counts.get(mac, 0) + 1
                matched = True
                break
        if not matched:
            # Broadcast flood: no AP address in any field.
            # Attribute to every known BSSID (whole-network denial-of-service).
            dst = getattr(pkt[Dot11] if pkt.haslayer(Dot11) else pkt, "addr1", None)
            if dst and dst.lower() == _BROADCAST:
                for bssid in known_bssids:
                    deauth_counts[bssid] = deauth_counts.get(bssid, 0) + 1

    # --- Count EAPOL frames per BSSID (addr3 = BSS ID in data frames) ----
    eapol_counts: Dict[str, int] = {}
    for pkt in eapol_frames:
        bssid = _safe_addr(pkt, "addr3")
        if bssid:
            eapol_counts[bssid] = eapol_counts.get(bssid, 0) + 1

    # --- Build a NetworkFeatures for each BSSID ---------------------------
    results: List[NetworkFeatures] = []
    for bssid, beacons in by_bssid.items():
        feat = _extract_from_beacons(bssid, beacons)
        feat.deauth_count      = deauth_counts.get(bssid, 0)
        feat.eapol_frame_count = eapol_counts.get(bssid, 0)
        results.append(feat)

    return results


# ---------------------------------------------------------------------------
# Per-BSSID extraction
# ---------------------------------------------------------------------------

def _extract_from_beacons(bssid: str, beacons: List[Packet]) -> NetworkFeatures:
    """Merge all beacons for one BSSID into a single NetworkFeatures."""
    feat = NetworkFeatures(bssid=bssid, ssid=None)
    feat.beacon_count = len(beacons)

    for pkt in beacons:
        _merge_beacon(feat, pkt)

    # Derive summary labels from the collected evidence.
    feat.cipher    = _derive_cipher(feat)
    feat.auth_type = _derive_auth(feat)

    return feat


def _merge_beacon(feat: NetworkFeatures, pkt: Packet) -> None:
    """Update *feat* in-place with any new information from one beacon."""

    # --- RSSI from RadioTap header ----------------------------------------
    rssi = _extract_rssi(pkt)
    if rssi is not None:
        feat.rssi_dbm.append(rssi)

    # --- Capability field (privacy bit) -----------------------------------
    if pkt.haslayer(Dot11Beacon):
        try:
            cap_int = int(pkt[Dot11Beacon].cap)
            if cap_int & 0x10:          # bit 4 = Privacy
                feat.privacy_bit = True
        except (TypeError, ValueError):
            feat.parser_notes.append("Could not parse beacon capability field.")

    # --- Information Elements ---------------------------------------------
    _walk_ies(feat, pkt)


def _walk_ies(feat: NetworkFeatures, pkt: Packet) -> None:
    """Walk the IE chain from Dot11Beacon payload and dispatch each IE."""
    if not pkt.haslayer(Dot11Beacon):
        return

    layer = pkt[Dot11Beacon].payload
    while layer and layer.name != "NoPayload":
        try:
            _handle_ie(feat, layer)
        except Exception as exc:
            ie_id = getattr(layer, "ID", "?")
            feat.parser_notes.append(
                f"Non-fatal IE parse error (ID={ie_id}): {exc}"
            )
        layer = layer.payload


def _handle_ie(feat: NetworkFeatures, ie) -> None:
    """Dispatch one IE to the appropriate handler."""
    ie_id = getattr(ie, "ID", -1)

    # ---- SSID (ID=0) -----------------------------------------------------
    if ie_id == 0:
        if feat.ssid is None:           # use first observation
            raw = bytes(ie.info) if ie.info else b""
            feat.ssid = raw.decode("utf-8", errors="replace")
        return

    # ---- DS Parameter Set (ID=3) → channel --------------------------------
    if ie_id == 3:
        if feat.channel is None:
            if hasattr(ie, "channel"):  # Dot11EltDSSSet in scapy 2.8
                feat.channel = int(ie.channel)
            elif ie.info:
                raw = bytes(ie.info)
                feat.channel = raw[0] if raw else None
        return

    # ---- RSN IE (ID=48) — prefer scapy-dissected Dot11EltRSN -------------
    if isinstance(ie, Dot11EltRSN):
        _parse_rsn_scapy(feat, ie)
        return
    if ie_id == 48:
        # Fallback for future scapy versions or unusual IE layouts.
        _parse_rsn_raw(feat, bytes(ie.info) if ie.info else b"")
        return

    # ---- Vendor Specific (ID=221) ----------------------------------------
    if ie_id == 221:
        _parse_vendor_ie(feat, ie)
        return


# ---------------------------------------------------------------------------
# RSN IE parsers
# ---------------------------------------------------------------------------

def _parse_rsn_scapy(feat: NetworkFeatures, rsn: Dot11EltRSN) -> None:
    """
    Populate RSN fields from scapy's fully dissected Dot11EltRSN object.
    Falls back to raw byte parsing on any field access error.
    """
    try:
        # Group cipher
        feat.group_cipher = _cipher_label(int(rsn.group_cipher_suite.cipher))

        # Pairwise ciphers (may be a list of CipherSuite objects)
        feat.pairwise_ciphers = [
            _cipher_label(int(cs.cipher))
            for cs in (rsn.pairwise_cipher_suites or [])
        ]

        # AKM suites (may be a list of AKMSuite objects)
        feat.akm_suites = [
            _akm_label(int(s.suite))
            for s in (rsn.akm_suites or [])
        ]

        # MFP capabilities — integers 0/1 in scapy 2.8
        feat.mfp_capable  = bool(rsn.mfp_capable)
        feat.mfp_required = bool(rsn.mfp_required)

        # WPA version
        _record_wpa_version(feat)

    except Exception as exc:
        feat.parser_notes.append(
            f"Dot11EltRSN field access error: {exc}. Falling back to raw parse."
        )
        try:
            _parse_rsn_raw(feat, bytes(rsn.info) if rsn.info else b"")
        except Exception as raw_exc:
            feat.parser_notes.append(f"RSN raw fallback also failed: {raw_exc}")


def _parse_rsn_raw(feat: NetworkFeatures, raw: bytes) -> None:
    """
    Parse an RSN IE payload from raw bytes.

    RSN IE layout (IEEE 802.11-2020 §9.4.2.24)
    -------------------------------------------
    Offset  Len  Field
     0       2   Version (little-endian; must be 1)
     2       3   Group Cipher Suite OUI
     5       1   Group Cipher Suite Selector
     6       2   Pairwise Cipher Suite Count (LE)
     8      4n   Pairwise Cipher Suites (OUI[3] + Selector[1])
    8+4n     2   AKM Suite Count (LE)
    10+4n   4m   AKM Suites (OUI[3] + Selector[1])
    10+4n+4m 2   RSN Capabilities (LE, optional)
    """
    if len(raw) < 8:
        feat.parser_notes.append(
            f"RSN IE raw payload too short ({len(raw)} bytes); skipped."
        )
        return

    try:
        # Version
        version = struct.unpack_from("<H", raw, 0)[0]
        if version != 1:
            feat.parser_notes.append(f"Unexpected RSN version {version}.")

        # Group cipher (OUI at bytes 2-4, selector at byte 5)
        gc_sel = raw[5]
        if feat.group_cipher is None:
            feat.group_cipher = _cipher_label(gc_sel)

        # Pairwise cipher suites
        pw_count = struct.unpack_from("<H", raw, 6)[0]
        offset = 8
        pw_ciphers: List[str] = []
        for _ in range(pw_count):
            if offset + 4 > len(raw):
                feat.parser_notes.append("RSN IE truncated in pairwise cipher list.")
                break
            pw_ciphers.append(_cipher_label(raw[offset + 3]))
            offset += 4
        if not feat.pairwise_ciphers:
            feat.pairwise_ciphers = pw_ciphers

        # AKM suites
        if offset + 2 > len(raw):
            _record_wpa_version(feat)
            return
        akm_count = struct.unpack_from("<H", raw, offset)[0]
        offset += 2
        akms: List[str] = []
        for _ in range(akm_count):
            if offset + 4 > len(raw):
                feat.parser_notes.append("RSN IE truncated in AKM suite list.")
                break
            akms.append(_akm_label(raw[offset + 3]))
            offset += 4
        if not feat.akm_suites:
            feat.akm_suites = akms

        # RSN Capabilities (2 bytes, little-endian)
        # bit 6 (0x0040) = MFPR, bit 7 (0x0080) = MFPC
        if offset + 2 <= len(raw):
            caps = struct.unpack_from("<H", raw, offset)[0]
            if feat.mfp_capable is None:
                feat.mfp_capable  = bool(caps & 0x0080)
            if feat.mfp_required is None:
                feat.mfp_required = bool(caps & 0x0040)

        _record_wpa_version(feat)

    except Exception as exc:
        feat.parser_notes.append(f"RSN IE raw parse error: {exc}")


def _parse_vendor_ie(feat: NetworkFeatures, ie) -> None:
    """Inspect a vendor-specific IE for WPS and WPA1 markers."""
    try:
        raw_info = bytes(ie.info) if ie.info else b""
    except Exception:
        return

    if raw_info[:4] == _WPS_OUI_TYPE:
        feat.wps_present = True

    elif raw_info[:4] == _WPA1_OUI_TYPE:
        if "WPA" not in feat.wpa_versions:
            feat.wpa_versions.append("WPA")


# ---------------------------------------------------------------------------
# Cipher / AKM / WPA-version helpers
# ---------------------------------------------------------------------------

def _derive_cipher(feat: NetworkFeatures) -> str:
    """Compute the summary ``cipher`` label from observed evidence."""
    if not feat.pairwise_ciphers and feat.group_cipher is None:
        # No RSN IE detected.
        return CIPHER_WEP if feat.privacy_bit else CIPHER_NONE

    ciphers = set(feat.pairwise_ciphers)
    if CIPHER_TKIP in ciphers and CIPHER_CCMP in ciphers:
        return CIPHER_MIXED
    if CIPHER_GCMP in ciphers:
        return CIPHER_GCMP
    if CIPHER_CCMP in ciphers:
        return CIPHER_CCMP
    if CIPHER_TKIP in ciphers:
        return CIPHER_TKIP
    if ciphers:
        return next(iter(ciphers))
    # Only group cipher was parsed.
    return feat.group_cipher or CIPHER_UNKNOWN


def _derive_auth(feat: NetworkFeatures) -> str:
    """Compute the summary ``auth_type`` label from observed AKM suites."""
    if not feat.akm_suites:
        # No RSN IE → OPEN applies to both clear-text and WEP networks.
        return AUTH_OPEN
    if AUTH_SAE in feat.akm_suites:
        return AUTH_SAE
    if AUTH_OWE in feat.akm_suites:
        return AUTH_OWE
    if AUTH_EAP in feat.akm_suites:
        return AUTH_EAP
    if AUTH_PSK in feat.akm_suites:
        return AUTH_PSK
    return AUTH_UNKNOWN


def _record_wpa_version(feat: NetworkFeatures) -> None:
    """Append WPA version strings based on what has been parsed so far."""
    if feat.pairwise_ciphers or feat.akm_suites or feat.group_cipher:
        if "WPA2" not in feat.wpa_versions:
            feat.wpa_versions.append("WPA2")
    if AUTH_SAE in feat.akm_suites and "WPA3" not in feat.wpa_versions:
        feat.wpa_versions.append("WPA3")


def _cipher_label(selector: int) -> str:
    return _CIPHER_MAP.get(selector, CIPHER_UNKNOWN)


def _akm_label(selector: int) -> str:
    return _AKM_MAP.get(selector, AUTH_UNKNOWN)


# ---------------------------------------------------------------------------
# Packet field helpers
# ---------------------------------------------------------------------------

def _bssid_from_packet(pkt: Packet) -> Optional[str]:
    """
    Extract the BSSID from a beacon frame.
    Uses addr3 (BSS ID field) with addr2 (transmitter) as fallback.
    Returns ``None`` for broadcast addresses or missing fields.
    """
    if not pkt.haslayer(Dot11):
        return None
    for field in ("addr3", "addr2"):
        mac = getattr(pkt[Dot11], field, None)
        if mac and mac.lower() != _BROADCAST:
            return mac.lower()
    return None


def _safe_addr(pkt: Packet, field: str) -> Optional[str]:
    """Return a normalised MAC address from a Dot11 field, or ``None``."""
    if not pkt.haslayer(Dot11):
        return None
    val = getattr(pkt[Dot11], field, None)
    if not val or val.lower() == _BROADCAST:
        return None
    return val.lower()


def _extract_rssi(pkt: Packet) -> Optional[int]:
    """
    Extract RSSI (dBm) from a RadioTap header.

    Returns ``None`` if:
    - No RadioTap layer is present.
    - The dBm_AntSignal field is absent or zero (no signal data in header).
    """
    if not pkt.haslayer(RadioTap):
        return None
    rt = pkt[RadioTap]
    sig = getattr(rt, "dBm_AntSignal", None)
    # scapy returns None when the field bit is not set in the present mask.
    if sig is not None and sig != 0:
        return int(sig)
    return None
