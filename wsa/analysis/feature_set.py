"""
Unified feature model for wireless network observations.

Design principles
-----------------
* Every field documents what ``None`` or an empty collection means.
* Fields are only populated from observed evidence; any inference is noted.
* No security judgements are made here — that is the rule engine's job (Stage 3).
* EAPOL frames are counted; no claim of a complete handshake is made.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# String constants — cipher / AKM summary labels
# ---------------------------------------------------------------------------

CIPHER_NONE    = "NONE"     # Open: no encryption, privacy bit absent
CIPHER_WEP     = "WEP"      # Privacy bit set, no RSN IE present
CIPHER_TKIP    = "TKIP"     # RSN IE, TKIP-only pairwise cipher
CIPHER_CCMP    = "CCMP"     # RSN IE, AES-CCMP pairwise cipher
CIPHER_GCMP    = "GCMP"     # RSN IE, AES-GCMP pairwise cipher
CIPHER_MIXED   = "MIXED"    # RSN IE, both TKIP and CCMP offered
CIPHER_UNKNOWN = "UNKNOWN"  # RSN IE present, selector not in known set

AUTH_OPEN    = "OPEN"     # No RSN IE (open or WEP network)
AUTH_PSK     = "PSK"      # AKM selector 2, 4, or 6
AUTH_SAE     = "SAE"      # AKM selector 8 or 9 (WPA3-Personal)
AUTH_EAP     = "EAP"      # AKM selector 1, 3, or 5 (802.1X Enterprise)
AUTH_OWE     = "OWE"      # AKM selector 18
AUTH_UNKNOWN = "UNKNOWN"  # AKM selector not in known set


@dataclass
class NetworkFeatures:
    """
    All security-relevant features extracted from frames of one access point.

    One instance is produced per unique BSSID.  Fields are merged from every
    beacon frame seen for that BSSID during the capture.

    Absent-vs-unknown policy
    ------------------------
    ``None``       → the field could not be read from any captured frame
                     (IE was absent, frame was malformed, etc.).
    ``[]`` / ``{}``→ zero instances observed (not absent; structurally empty).
    String const   → directly observed or deterministically derived; see each
                     field's docstring for the derivation rule.
    """

    # ------------------------------------------------------------------
    # Identity (always populated)
    # ------------------------------------------------------------------
    bssid: str
    """AP MAC address, lower-case colon-separated."""

    ssid: Optional[str]
    """
    Network name from the SSID IE (ID=0).

    ``None``  → SSID IE was absent from every beacon for this BSSID.
    ``''``    → SSID IE was present but contained an empty string
                (commonly used for hidden / cloaked SSIDs).
    Any other string → the observed SSID; non-UTF-8 bytes are replaced.
    """

    # ------------------------------------------------------------------
    # RF / Physical
    # ------------------------------------------------------------------
    channel: Optional[int] = None
    """
    Operating channel from the DS Parameter Set IE (ID=3).
    ``None`` if the IE was absent in all beacons for this BSSID.
    """

    rssi_dbm: List[int] = field(default_factory=list)
    """
    Per-frame RSSI readings (dBm) from the RadioTap header.
    Empty list if no RadioTap signal field was present in any frame.
    Raw values only; no calibration or averaging is performed here.
    """

    # ------------------------------------------------------------------
    # Capability bits (directly from Dot11Beacon.cap)
    # ------------------------------------------------------------------
    privacy_bit: bool = False
    """
    Privacy capability bit (bit 4 of the 802.11 capability field).
    ``True`` indicates the AP advertises encryption.
    This is a low-level indicator; the actual cipher is in ``cipher``.
    """

    # ------------------------------------------------------------------
    # Encryption — derived from RSN IE analysis
    # ------------------------------------------------------------------
    group_cipher: Optional[str] = None
    """
    Group (broadcast / multicast) cipher suite label from the RSN IE.
    ``None`` if no RSN IE was found.
    One of: TKIP, CCMP, GCMP, WEP, UNKNOWN.
    """

    pairwise_ciphers: List[str] = field(default_factory=list)
    """
    Pairwise (unicast) cipher suite labels offered in the RSN IE.
    Empty list if no RSN IE was found.
    Elements: TKIP, CCMP, GCMP, UNKNOWN.
    """

    cipher: str = CIPHER_UNKNOWN
    """
    Summary cipher label for downstream rule evaluation.

    Derivation (in priority order):
    1. No RSN IE and privacy bit absent  → NONE
    2. No RSN IE but privacy bit set     → WEP
    3. RSN IE; TKIP and CCMP both offered → MIXED
    4. RSN IE; GCMP in pairwise set      → GCMP
    5. RSN IE; CCMP in pairwise set      → CCMP
    6. RSN IE; TKIP only                 → TKIP
    7. RSN IE; selector not recognised   → UNKNOWN
    """

    # ------------------------------------------------------------------
    # Authentication / Key Management — derived from RSN IE AKM suites
    # ------------------------------------------------------------------
    akm_suites: List[str] = field(default_factory=list)
    """
    AKM suite labels from the RSN IE.
    Empty list if no RSN IE was found.
    Elements: PSK, SAE, EAP, OWE, UNKNOWN.
    """

    auth_type: str = AUTH_UNKNOWN
    """
    Summary AKM label for downstream rule evaluation.

    Derivation:
    - SAE present in akm_suites           → SAE
    - OWE present in akm_suites           → OWE
    - EAP present, SAE absent             → EAP
    - PSK present, SAE/EAP absent         → PSK
    - No RSN IE (open or WEP)             → OPEN
    - RSN IE but no recognised AKM suite  → UNKNOWN
    """

    wpa_versions: List[str] = field(default_factory=list)
    """
    WPA version strings inferred from IEs present in the beacon.
    Possible elements:
      'WPA'  — vendor-specific WPA1 IE (OUI 00:50:F2:01) detected.
      'WPA2' — RSN IE (ID=48) with version=1 detected.
      'WPA3' — SAE AKM suite detected within an RSN IE.
    Empty for open or WEP networks.
    """

    # ------------------------------------------------------------------
    # Management Frame Protection (from RSN capabilities field)
    # ------------------------------------------------------------------
    mfp_capable: Optional[bool] = None
    """
    IEEE 802.11w MFPC (Management Frame Protection Capable) bit.
    ``None`` if no RSN IE was present (MFP is undefined without RSN).
    """

    mfp_required: Optional[bool] = None
    """
    IEEE 802.11w MFPR (Management Frame Protection Required) bit.
    ``None`` if no RSN IE was present.
    """

    # ------------------------------------------------------------------
    # Wi-Fi Protected Setup
    # ------------------------------------------------------------------
    wps_present: bool = False
    """True if a WPS vendor-specific IE (OUI+type 00:50:F2:04) was seen."""

    # ------------------------------------------------------------------
    # Frame counts
    # ------------------------------------------------------------------
    beacon_count: int = 0
    """Number of beacon frames observed for this BSSID."""

    deauth_count: int = 0
    """
    Number of deauthentication and disassociation frames where addr2 or
    addr3 matches this BSSID.  Counts both legitimate and spoofed frames;
    the two cannot be distinguished without MFP.
    """

    eapol_frame_count: int = 0
    """
    Raw count of EAPOL frames associated with this BSSID (via addr3).

    This is a frame count only.  No claim of a complete 4-way handshake is
    made here.  A complete handshake determination requires reliable
    identification of all four message types from EAPOL-Key frame fields,
    which is deferred to a later stage.
    """

    # ------------------------------------------------------------------
    # Parser observations
    # ------------------------------------------------------------------
    parser_notes: List[str] = field(default_factory=list)
    """
    Non-fatal observations recorded during parsing, e.g.:
    - Truncated or malformed IEs.
    - Unrecognised IE selectors.
    - Fields that could not be decoded.
    Does not indicate data loss; other fields may still be valid.
    """

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def avg_rssi(self) -> Optional[float]:
        """Mean RSSI in dBm, or ``None`` if no readings were collected."""
        return sum(self.rssi_dbm) / len(self.rssi_dbm) if self.rssi_dbm else None

    @property
    def hidden_ssid(self) -> bool:
        """
        True when the SSID IE was present but contained an empty string.
        This is distinct from ``ssid is None`` (IE absent).
        """
        return self.ssid == ""

    def __post_init__(self) -> None:
        self.bssid = self.bssid.lower()


@dataclass
class ScanFeatures:
    """
    Aggregate features from one PCAP capture session.

    Contains per-network observations (one ``NetworkFeatures`` per BSSID)
    and session-level counts.
    """

    source_file: str
    """Absolute or relative path to the PCAP file that was parsed."""

    data_source: str
    """
    Provenance label supplied by the caller: 'simulated' or 'real'.
    Never inferred from file content.
    """

    total_frames: int = 0
    """Total number of packets returned by the PCAP reader."""

    networks: List[NetworkFeatures] = field(default_factory=list)
    """One entry per unique BSSID discovered in the capture."""

    total_probe_requests: int = 0
    """Total probe-request frames across the entire capture."""

    total_deauth_frames: int = 0
    """Total deauth / disassoc frames across the entire capture."""

    total_eapol_frames: int = 0
    """Total EAPOL frames across the entire capture (all BSSIDs)."""

    parse_errors: List[str] = field(default_factory=list)
    """
    Non-fatal errors recorded during parsing.
    Individual frame errors do not abort the scan; they are collected here.
    """

    @property
    def network_count(self) -> int:
        """Number of unique BSSIDs discovered."""
        return len(self.networks)
