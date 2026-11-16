"""
=============================================================================
SIMULATED TEST DATA GENERATOR  —  Wireless Security Assessment Project
=============================================================================

DATA PROVENANCE: SYNTHETIC / SIMULATED
---------------------------------------
This script generates artificial IEEE 802.11 PCAP files using the scapy
library.  It does NOT perform any live wireless scanning, deauthentication
attacks, password cracking, or any other active wireless operation.
No physical Wi-Fi adapter is used or required.

All MAC addresses are randomly generated and do not correspond to real
devices or networks.

Purpose
-------
Provide clearly labelled synthetic captures so that every analysis feature
(frame parsing, rule evaluation, report generation, comparison) can be
developed and tested on a Kali Linux VM with no Wi-Fi hardware.

Generated files (written to data/simulated/ by default)
--------------------------------------------------------
  open_network.pcapng      — Open AP, no encryption
  wep_network.pcapng       — WEP-encrypted AP (deprecated)
  wpa2_personal.pcapng     — WPA2-PSK/CCMP, WPS on, 4-way handshake
  wpa3_network.pcapng      — WPA3-SAE/CCMP, MFP required
  deauth_flood.pcapng      — WPA2 AP + 20 deauth frames (simulated flood)
  mixed_environment.pcapng — All scenarios merged into one file

Usage
-----
  python tests/generators/generate_test_pcaps.py
  python tests/generators/generate_test_pcaps.py --output /custom/dir/

=============================================================================
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Scapy imports — grouped so the ImportError message is clear
# ---------------------------------------------------------------------------
try:
    from scapy.all import wrpcap
    from scapy.layers.dot11 import (
        Dot11,
        Dot11Beacon,
        Dot11Deauth,
        Dot11Elt,
        Dot11ProbeReq,
        RadioTap,
    )
    from scapy.packet import Raw
except ImportError as exc:  # pragma: no cover
    sys.exit(
        f"[ERROR] scapy is not installed: {exc}\n"
        "Install it with:  pip install scapy"
    )

# ---------------------------------------------------------------------------
# Constants — 802.11 / RSN field values
# ---------------------------------------------------------------------------

# Beacon capability field (16-bit little-endian)
CAP_ESS = 0x0001          # Extended Service Set (infrastructure AP)
CAP_PRIVACY = 0x0010      # WEP/WPA privacy bit

# Dot11 type/subtype values
TYPE_MGMT = 0
SUBTYPE_BEACON = 8
SUBTYPE_PROBE_REQ = 4
SUBTYPE_DEAUTH = 12
TYPE_DATA = 2
SUBTYPE_DATA = 0

# RSN cipher suite OUIs  (00:0F:AC:<selector>)
_OUI_RSN = b"\x00\x0f\xac"
CIPHER_CCMP = _OUI_RSN + b"\x04"   # AES-CCMP (strong)
CIPHER_TKIP = _OUI_RSN + b"\x02"   # TKIP (deprecated)

# RSN AKM suite OUIs
AKM_PSK = _OUI_RSN + b"\x02"       # WPA2-Personal
AKM_SAE = _OUI_RSN + b"\x08"       # WPA3-Personal (SAE)

# RSN Capabilities (2-byte little-endian, byte-0 bits)
# bit 6 = MFPR (Management Frame Protection Required)
# bit 7 = MFPC (Management Frame Protection Capable)
RSN_CAP_NONE = b"\x00\x00"
RSN_CAP_MFP_CAPABLE = b"\x80\x00"     # MFPC=1, MFPR=0
RSN_CAP_MFP_REQUIRED = b"\xc0\x00"   # MFPC=1, MFPR=1

# WPS vendor-specific IE OUI+type  (00:50:F2:04 = Wi-Fi Protected Setup)
WPS_OUI_TYPE = b"\x00\x50\xf2\x04"

# EAPOL ethertype embedded in LLC/SNAP header inside a data frame
# Structure: DSAP=AA, SSAP=AA, Ctrl=03, OUI=000000, EtherType=888E
LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

# Broadcast / wildcard addresses
BROADCAST = "ff:ff:ff:ff:ff:ff"

# Deauthentication reason codes (RFC 3580 / IEEE 802.11)
DEAUTH_REASON_UNSPECIFIED = 1
DEAUTH_REASON_CLASS3 = 7   # Class 3 frame from non-associated STA


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _random_mac() -> str:
    """Return a random locally-administered unicast MAC (aa:...) ."""
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02   # locally administered, unicast
    return ":".join(f"{b:02x}" for b in octets)


def _build_rsn_ie(
    group_cipher: bytes,
    pairwise_cipher: bytes,
    akm: bytes,
    rsn_caps: bytes,
) -> bytes:
    """
    Construct the raw payload for an RSN Information Element (IE ID = 48).

    RSN IE layout (IEEE 802.11-2020 §9.4.2.24):
      2  Version (always 0x0100 = version 1, little-endian)
      4  Group Data Cipher Suite
      2  Pairwise Cipher Suite Count  (we always use 1)
      4  Pairwise Cipher Suite
      2  AKM Suite Count              (we always use 1)
      4  AKM Suite
      2  RSN Capabilities
    """
    return (
        b"\x01\x00"          # Version 1
        + group_cipher       # Group cipher suite
        + b"\x01\x00"        # Pairwise count = 1
        + pairwise_cipher    # Pairwise cipher suite
        + b"\x01\x00"        # AKM count = 1
        + akm                # AKM suite
        + rsn_caps           # RSN capabilities
    )


def _build_wps_ie() -> bytes:
    """
    Minimal WPS vendor-specific IE payload.
    OUI+type (4 bytes) followed by a WPS attribute:
    Attribute ID 0x104A (Version), length 1, value 0x10 (WPS version 1.0).
    """
    return WPS_OUI_TYPE + b"\x10\x4a\x00\x01\x10"


def _beacon(
    bssid: str,
    ssid: str,
    channel: int,
    cap: int,
    extra_ies: list[bytes] | None = None,
) -> "scapy packet":
    """
    Craft a single 802.11 Beacon frame.

    Parameters
    ----------
    bssid     : AP MAC address string (e.g. 'aa:bb:cc:dd:ee:ff')
    ssid      : Network name string (empty string = hidden SSID)
    channel   : 802.11 channel number (1-14 for 2.4 GHz, 36+ for 5 GHz)
    cap       : Capability field integer (CAP_ESS, CAP_ESS | CAP_PRIVACY, …)
    extra_ies : Additional raw IE payloads appended after the DSset IE.
                Each entry is (ie_id: int, ie_payload: bytes).
    """
    pkt = (
        RadioTap()
        / Dot11(
            type=TYPE_MGMT,
            subtype=SUBTYPE_BEACON,
            addr1=BROADCAST,
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Beacon(cap=cap)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )

    for ie_id, ie_payload in (extra_ies or []):
        pkt = pkt / Dot11Elt(ID=ie_id, info=ie_payload)

    return pkt


def _probe_request(client_mac: str, ssid: str) -> "scapy packet":
    """Craft a Probe Request frame from a client looking for a specific SSID."""
    return (
        RadioTap()
        / Dot11(
            type=TYPE_MGMT,
            subtype=SUBTYPE_PROBE_REQ,
            addr1=BROADCAST,
            addr2=client_mac,
            addr3=BROADCAST,
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    )


def _deauth(bssid: str, target: str, reason: int = DEAUTH_REASON_CLASS3) -> "scapy packet":
    """
    Craft a Deauthentication frame.

    In a real deauth flood the attacker spoofs the AP's BSSID.  Here we
    simply simulate that pattern in static packet data — no actual radio
    transmission occurs.

    Parameters
    ----------
    bssid  : AP BSSID (spoofed source in a real attack; here just static data)
    target : Destination MAC (broadcast = disconnect all clients)
    reason : IEEE 802.11 reason code
    """
    return (
        RadioTap()
        / Dot11(
            type=TYPE_MGMT,
            subtype=SUBTYPE_DEAUTH,
            addr1=target,
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Deauth(reason=reason)
    )


def _eapol_key_frame(src: str, dst: str, bssid: str) -> "scapy packet":
    """
    Craft a minimal EAPOL-Key frame embedded in an 802.11 Data frame.

    Structure inside the data payload:
      LLC/SNAP header for EtherType 0x888E (EAPOL)
      EAPOL header: version=2, type=3 (Key), length=95
      EAPOL-Key body: 95 zero bytes (enough for the parser to detect EAPOL)

    This simulates one message of the WPA2 4-way handshake without encoding
    any real cryptographic material.
    """
    eapol_version = 2
    eapol_type_key = 3
    key_body_len = 95
    eapol_header = bytes([eapol_version, eapol_type_key]) + key_body_len.to_bytes(2, "big")
    eapol_body = bytes(key_body_len)
    payload = LLC_SNAP_EAPOL + eapol_header + eapol_body

    return (
        RadioTap()
        / Dot11(
            type=TYPE_DATA,
            subtype=SUBTYPE_DATA,
            addr1=dst,
            addr2=src,
            addr3=bssid,
        )
        / Raw(load=payload)
    )


# ---------------------------------------------------------------------------
# Per-scenario generators
# ---------------------------------------------------------------------------

def _make_open_network(bssid: str) -> list:
    """
    Scenario: Open AP — no encryption, no authentication.

    Frames generated
    ----------------
    10  Beacon frames  (no RSN IE, privacy bit NOT set → cipher = NONE)
     5  Probe request frames from random client MACs
    """
    ssid = "OpenCafe"
    packets: list = []

    for _ in range(10):
        packets.append(_beacon(bssid, ssid, channel=6, cap=CAP_ESS))

    for _ in range(5):
        packets.append(_probe_request(_random_mac(), ssid))

    return packets


def _make_wep_network(bssid: str) -> list:
    """
    Scenario: WEP-encrypted AP.

    WEP is represented by the Privacy capability bit being set with NO RSN IE.
    WEP was deprecated by IEEE 802.11 in 2004 and is completely broken.

    Frames generated
    ----------------
    10  Beacon frames  (privacy bit = 1, no RSN IE → cipher = WEP)
     5  Probe request frames
    """
    ssid = "LegacyCorpNet"
    packets: list = []

    for _ in range(10):
        packets.append(
            _beacon(bssid, ssid, channel=11, cap=CAP_ESS | CAP_PRIVACY)
        )

    for _ in range(5):
        packets.append(_probe_request(_random_mac(), ssid))

    return packets


def _make_wpa2_personal(bssid: str) -> list:
    """
    Scenario: WPA2-Personal (PSK/CCMP) with WPS enabled.

    Security properties encoded in the RSN IE
    ------------------------------------------
    Group cipher   : CCMP (AES)
    Pairwise cipher: CCMP (AES)
    AKM            : PSK  (pre-shared key)
    MFP            : Capable (MFPC=1), NOT Required (MFPR=0)

    WPS vendor-specific IE is also included (trigger for AUTH-001 HIGH).

    Frames generated
    ----------------
    10  Beacon frames
     4  EAPOL-Key frames  (simulated 4-way handshake between AP and client)
     5  Probe request frames
    """
    ssid = "HomeNetwork"
    client_mac = _random_mac()

    rsn_payload = _build_rsn_ie(
        group_cipher=CIPHER_CCMP,
        pairwise_cipher=CIPHER_CCMP,
        akm=AKM_PSK,
        rsn_caps=RSN_CAP_MFP_CAPABLE,
    )
    wps_payload = _build_wps_ie()

    extra_ies = [
        (48, rsn_payload),   # IE ID 48 = RSN
        (221, wps_payload),  # IE ID 221 = Vendor Specific (WPS)
    ]

    packets: list = []

    for _ in range(10):
        packets.append(
            _beacon(bssid, ssid, channel=1, cap=CAP_ESS | CAP_PRIVACY, extra_ies=extra_ies)
        )

    # Simulate the 4 messages of the WPA2 4-way handshake
    # msg1, msg3: AP → client (addr2=bssid, addr1=client)
    # msg2, msg4: client → AP (addr2=client, addr1=bssid)
    handshake_directions = [
        (bssid, client_mac),   # msg1: AP → client
        (client_mac, bssid),   # msg2: client → AP
        (bssid, client_mac),   # msg3: AP → client
        (client_mac, bssid),   # msg4: client → AP
    ]
    for src, dst in handshake_directions:
        packets.append(_eapol_key_frame(src=src, dst=dst, bssid=bssid))

    for _ in range(5):
        packets.append(_probe_request(_random_mac(), ssid))

    return packets


def _make_wpa3_network(bssid: str) -> list:
    """
    Scenario: WPA3-Personal (SAE/CCMP) with Management Frame Protection required.

    Security properties
    -------------------
    Group cipher   : CCMP
    Pairwise cipher: CCMP
    AKM            : SAE  (Simultaneous Authentication of Equals)
    MFP            : Required (MFPC=1, MFPR=1) — mandatory for WPA3

    No WPS, no hidden SSID, no deauth flood.
    Expected findings: INFO only (AUTH-005 PSK note not applicable here).

    Frames generated
    ----------------
    10  Beacon frames
     3  Probe request frames
    """
    ssid = "SecureNet5G"

    rsn_payload = _build_rsn_ie(
        group_cipher=CIPHER_CCMP,
        pairwise_cipher=CIPHER_CCMP,
        akm=AKM_SAE,
        rsn_caps=RSN_CAP_MFP_REQUIRED,
    )
    extra_ies = [(48, rsn_payload)]

    packets: list = []

    for _ in range(10):
        packets.append(
            _beacon(bssid, ssid, channel=36, cap=CAP_ESS | CAP_PRIVACY, extra_ies=extra_ies)
        )

    for _ in range(3):
        packets.append(_probe_request(_random_mac(), ssid))

    return packets


def _make_deauth_flood(bssid: str) -> list:
    """
    Scenario: WPA2 AP subject to a deauthentication frame flood.

    Context
    -------
    The AP uses WPA2-PSK/CCMP but has NO Management Frame Protection (MFP).
    Without MFP (IEEE 802.11w), deauthentication frames are unauthenticated
    and can be trivially forged.  Here we simulate 20 deauth frames targeting
    broadcast (disconnecting all clients) — a pattern seen in DOS and
    handshake-capture attacks.

    NOTE: No real radio transmission or attack occurs.  These are static
    packet objects written to a file.

    Frames generated
    ----------------
    10  Beacon frames  (WPA2-PSK, MFP caps = 0x0000)
    20  Deauthentication frames  (broadcast target, attacker source MAC)
     3  Probe request frames
    """
    ssid = "TargetNetwork"
    attacker_mac = _random_mac()   # simulated attacker/spoofed source

    rsn_payload = _build_rsn_ie(
        group_cipher=CIPHER_CCMP,
        pairwise_cipher=CIPHER_CCMP,
        akm=AKM_PSK,
        rsn_caps=RSN_CAP_NONE,   # No MFP at all
    )
    extra_ies = [(48, rsn_payload)]

    packets: list = []

    for _ in range(10):
        packets.append(
            _beacon(bssid, ssid, channel=6, cap=CAP_ESS | CAP_PRIVACY, extra_ies=extra_ies)
        )

    # 20 deauth frames — simulates a flood; each uses a different reason code
    # to mimic tool behaviour (e.g. aireplay-ng cycles through reason codes).
    # Target is broadcast to disconnect all associated clients simultaneously.
    for i in range(20):
        reason = (i % 7) + 1   # reason codes 1–7, cycling
        packets.append(_deauth(bssid=attacker_mac, target=BROADCAST, reason=reason))

    for _ in range(3):
        packets.append(_probe_request(_random_mac(), ssid))

    return packets


def _make_mixed_environment(all_scenario_packets: dict[str, list]) -> list:
    """
    Merge all scenario packets into a single interleaved capture.

    This simulates a multi-AP site survey where an analyst passively collects
    frames from multiple networks simultaneously on a single channel/time window.

    Parameters
    ----------
    all_scenario_packets : mapping of scenario_name → packet list
    """
    merged: list = []
    # Interleave round-robin so the capture looks realistic
    lists = list(all_scenario_packets.values())
    max_len = max(len(lst) for lst in lists)
    for i in range(max_len):
        for lst in lists:
            if i < len(lst):
                merged.append(lst[i])
    return merged


# ---------------------------------------------------------------------------
# Top-level generator
# ---------------------------------------------------------------------------

def generate_all_samples(output_dir: str | None = None) -> list[Path]:
    """
    Generate all six synthetic PCAP files and write them to *output_dir*.

    Parameters
    ----------
    output_dir : Directory path (str or Path).  Defaults to
                 ``<project_root>/data/simulated/``.

    Returns
    -------
    List of Path objects for every file written.
    """
    if output_dir is None:
        # Resolve relative to this script's location:
        # tests/generators/generate_test_pcaps.py  → project root → data/simulated
        project_root = Path(__file__).resolve().parent.parent.parent
        out = project_root / "data" / "simulated"
    else:
        out = Path(output_dir)

    out.mkdir(parents=True, exist_ok=True)

    # ---- Assign fixed, deterministic BSSIDs for reproducibility -----------
    # Using locally-administered MACs (byte-0 bit1 = 1) so they're clearly
    # not real OUI-assigned addresses.
    bssids = {
        "open":   "02:aa:bb:11:22:33",
        "wep":    "02:aa:bb:44:55:66",
        "wpa2":   "02:aa:bb:77:88:99",
        "wpa3":   "02:aa:bb:aa:bb:cc",
        "deauth": "02:aa:bb:dd:ee:ff",
    }

    # ---- Build all scenarios -----------------------------------------------
    scenario_packets: dict[str, list] = {
        "open":   _make_open_network(bssids["open"]),
        "wep":    _make_wep_network(bssids["wep"]),
        "wpa2":   _make_wpa2_personal(bssids["wpa2"]),
        "wpa3":   _make_wpa3_network(bssids["wpa3"]),
        "deauth": _make_deauth_flood(bssids["deauth"]),
    }

    # ---- Write individual files --------------------------------------------
    file_map = {
        "open_network.pcapng":   scenario_packets["open"],
        "wep_network.pcapng":    scenario_packets["wep"],
        "wpa2_personal.pcapng":  scenario_packets["wpa2"],
        "wpa3_network.pcapng":   scenario_packets["wpa3"],
        "deauth_flood.pcapng":   scenario_packets["deauth"],
    }

    written: list[Path] = []
    for filename, packets in file_map.items():
        path = out / filename
        wrpcap(str(path), packets)
        written.append(path)

    # ---- Write the mixed / merged file ------------------------------------
    mixed_packets = _make_mixed_environment(scenario_packets)
    mixed_path = out / "mixed_environment.pcapng"
    wrpcap(str(mixed_path), mixed_packets)
    written.append(mixed_path)

    return written


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate synthetic 802.11 PCAP files for the Wireless Security "
            "Assessment project.  No live wireless operations are performed."
        )
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        metavar="DIR",
        help="Output directory (default: data/simulated/)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    print("=" * 60)
    print("  Wireless Security Assessment — PCAP Sample Generator")
    print("  DATA PROVENANCE: SYNTHETIC / SIMULATED")
    print("  No live wireless operations are performed.")
    print("=" * 60)

    print(f"\nGenerating samples", end="")
    if args.output:
        print(f" → {args.output}")
    else:
        print(" → data/simulated/  (default)")
    print()

    paths = generate_all_samples(args.output)

    print(f"{'File':<35} {'Frames':>8}  {'Size':>10}")
    print("-" * 58)

    from scapy.all import rdpcap
    for p in paths:
        pkts = rdpcap(str(p))
        size_kb = p.stat().st_size / 1024
        print(f"  {p.name:<33} {len(pkts):>8}  {size_kb:>8.1f} KB")

    print()
    print(f"✓  {len(paths)} files written to: {paths[0].parent}")
    print()
    print("To verify with scapy:")
    print("  python3 -c \"from scapy.all import rdpcap; "
          f"p=rdpcap('{paths[-1]}'); print(len(p), 'frames')\"")


if __name__ == "__main__":
    main()
