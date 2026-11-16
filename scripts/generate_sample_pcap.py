#!/usr/bin/env python3
"""
Dynamic Wireless PCAP Generator for Security Assessment (WSA Kali).
Generates IEEE 802.11 PCAP/PCAPNG files with customized or randomized inputs
so you are not limited to static values.

Features:
- Pre-built threat profiles:
    * enterprise   : Corporate WPA3-SAE, 802.11w MFP Required (Risk: 0, Clean)
    * evil-twin    : Rogue AP impersonating legit network + high deauth flood (Risk: High/Critical)
    * iot          : Smart home Netgear AP with TKIP + WPS + ESP32/Echo IoT clients (Risk: High)
    * cafe         : Public open Wi-Fi with randomized client MAC probe requests (Risk: Critical)
    * dos-elevated : Medium-rate deauthentication anomaly triggering DOS-002 (Risk: Medium)
    * wep          : Legacy warehouse WEP encrypted network (Risk: Critical)
    * multi-ap     : Multi-channel enterprise environment with 3 distinct APs
- Custom parameter mode:
    --ssid, --channel, --encryption, --wps, --mfp, --deauth, --vendor, --clients
- Pure random mode (--random):
    Generates unique MACs, SSIDs, channels, and client distributions every execution!
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from pathlib import Path
from typing import List, Optional, Tuple

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
except ImportError as exc:
    sys.exit(f"[!] Scapy is required: {exc}. Run: pip install scapy")

# 802.11 Constants
CAP_ESS = 0x0001
CAP_PRIVACY = 0x0010

TYPE_MGMT = 0
SUBTYPE_BEACON = 8
SUBTYPE_PROBE_REQ = 4
SUBTYPE_DEAUTH = 12
TYPE_DATA = 2
SUBTYPE_DATA = 0

_OUI_RSN = b"\x00\x0f\xac"
CIPHER_CCMP = _OUI_RSN + b"\x04"
CIPHER_TKIP = _OUI_RSN + b"\x02"

AKM_PSK = _OUI_RSN + b"\x02"
AKM_SAE = _OUI_RSN + b"\x08"

RSN_CAP_NONE = b"\x00\x00"
RSN_CAP_MFP_CAPABLE = b"\x80\x00"
RSN_CAP_MFP_REQUIRED = b"\xc0\x00"

WPS_OUI_TYPE = b"\x00\x50\xf2\x04"
LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
BROADCAST = "ff:ff:ff:ff:ff:ff"
DEAUTH_REASON_CLASS3 = 7

# Known OUI vendors recognized by WSA device tracker
VENDOR_OUIS = {
    "apple": ["f0:18:98", "3c:22:fb", "ac:bc:32"],
    "intel": ["00:1e:67", "00:21:6a", "60:f2:62"],
    "cisco": ["00:1a:2b", "00:26:08", "00:12:17"],
    "tplink": ["50:c7:bf", "ec:08:6b", "98:48:27"],
    "netgear": ["00:24:81", "20:4e:7f", "00:26:f2"],
    "samsung": ["00:15:af", "34:23:87", "00:26:37"],
    "espressif": ["24:0a:c4", "30:ae:a4", "84:f3:eb"],
    "rpi": ["b8:27:eb", "dc:a6:32", "e4:5f:01"],
    "amazon": ["70:4f:57", "f0:27:2d"],
    "google": ["00:1a:11", "3c:5a:37", "d4:f5:47"],
}


def make_mac_for_vendor(vendor: str) -> str:
    """Generate a valid unicast OUI MAC address for a given vendor."""
    vendor_lower = vendor.lower()
    prefixes = VENDOR_OUIS.get(vendor_lower, ["00:1a:2b"])
    prefix = random.choice(prefixes)
    suffix = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
    return f"{prefix}:{suffix}".lower()


def make_random_mac(locally_administered: bool = False) -> str:
    """Generate a random MAC address."""
    octets = [random.randint(0, 255) for _ in range(6)]
    if locally_administered:
        octets[0] = (octets[0] & 0xFE) | 0x02
    else:
        octets[0] = (octets[0] & 0xFE) & ~0x02
    return ":".join(f"{b:02x}" for b in octets).lower()


def build_rsn_ie(group_cipher: bytes, pairwise_cipher: bytes, akm: bytes, rsn_caps: bytes) -> bytes:
    """Construct RSN IE ID=48 payload."""
    return (
        b"\x01\x00"
        + group_cipher
        + b"\x01\x00"
        + pairwise_cipher
        + b"\x01\x00"
        + akm
        + rsn_caps
    )


def build_wps_ie() -> bytes:
    """Minimal WPS vendor-specific IE."""
    return WPS_OUI_TYPE + b"\x10\x4a\x00\x01\x10"


def craft_radiotap(rssi_dbm: int = -50) -> RadioTap:
    """Craft RadioTap header with specified antenna signal level."""
    return RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi_dbm)


def craft_beacon(
    bssid: str,
    ssid: str,
    channel: int,
    cap: int,
    extra_ies: Optional[List[Tuple[int, bytes]]] = None,
    rssi_dbm: int = -50,
) -> Dot11:
    """Craft 802.11 Beacon frame with RadioTap."""
    pkt = (
        craft_radiotap(rssi_dbm)
        / Dot11(
            type=TYPE_MGMT,
            subtype=SUBTYPE_BEACON,
            addr1=BROADCAST,
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Beacon(cap=cap)
        / Dot11Elt(ID="SSID", info=ssid.encode("utf-8"))
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )
    for ie_id, ie_payload in (extra_ies or []):
        pkt = pkt / Dot11Elt(ID=ie_id, info=ie_payload)
    return pkt


def craft_probe_request(client_mac: str, ssid: str, rssi_dbm: int = -60) -> Dot11:
    """Craft 802.11 Probe Request frame."""
    return (
        craft_radiotap(rssi_dbm)
        / Dot11(
            type=TYPE_MGMT,
            subtype=SUBTYPE_PROBE_REQ,
            addr1=BROADCAST,
            addr2=client_mac,
            addr3=BROADCAST,
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=ssid.encode("utf-8"))
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    )


def craft_deauth(bssid: str, target_mac: str, reason: int = DEAUTH_REASON_CLASS3) -> Dot11:
    """Craft 802.11 Deauthentication frame."""
    return (
        craft_radiotap(-35)
        / Dot11(
            type=TYPE_MGMT,
            subtype=SUBTYPE_DEAUTH,
            addr1=target_mac,
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Deauth(reason=reason)
    )


def craft_eapol(src: str, dst: str, bssid: str) -> Dot11:
    """Craft 802.11 EAPOL handshake data frame."""
    eapol_header = bytes([2, 3]) + (95).to_bytes(2, "big")
    payload = LLC_SNAP_EAPOL + eapol_header + bytes(95)
    return (
        craft_radiotap(-52)
        / Dot11(
            type=TYPE_DATA,
            subtype=SUBTYPE_DATA,
            addr1=dst,
            addr2=src,
            addr3=bssid,
        )
        / Raw(load=payload)
    )


def generate_scenario_packets(
    ssid: str,
    bssid: str,
    channel: int = 6,
    encryption: str = "wpa2",
    wps: bool = False,
    mfp: str = "capable",
    deauth_count: int = 0,
    client_count: int = 3,
    client_vendors: Optional[List[str]] = None,
    rssi_dbm: int = -50,
) -> list:
    """Assemble a complete capture packet list based on input criteria."""
    enc = encryption.lower()
    mfp_setting = mfp.lower()
    extra_ies = []
    cap = CAP_ESS

    if enc == "open":
        cap = CAP_ESS
    elif enc == "wep":
        cap = CAP_ESS | CAP_PRIVACY
    elif enc in ("wpa2", "wpa3", "tkip", "mixed"):
        cap = CAP_ESS | CAP_PRIVACY
        group_cipher = CIPHER_CCMP
        pairwise_cipher = CIPHER_CCMP
        akm = AKM_PSK

        if enc == "wpa3":
            akm = AKM_SAE
            rsn_caps = RSN_CAP_MFP_REQUIRED
        elif enc == "tkip":
            group_cipher = CIPHER_TKIP
            pairwise_cipher = CIPHER_TKIP
            rsn_caps = RSN_CAP_NONE
        elif enc == "mixed":
            pairwise_cipher = CIPHER_TKIP
            rsn_caps = RSN_CAP_MFP_CAPABLE
        else:
            if mfp_setting == "required":
                rsn_caps = RSN_CAP_MFP_REQUIRED
            elif mfp_setting == "capable":
                rsn_caps = RSN_CAP_MFP_CAPABLE
            else:
                rsn_caps = RSN_CAP_NONE

        rsn_payload = build_rsn_ie(group_cipher, pairwise_cipher, akm, rsn_caps)
        extra_ies.append((48, rsn_payload))

        if wps:
            extra_ies.append((221, build_wps_ie()))

    packets = []
    # 1. Beacons
    for _ in range(12):
        packets.append(craft_beacon(bssid, ssid, channel, cap, extra_ies, rssi_dbm))

    # 2. Clients and probes
    default_vendors = ["apple", "intel", "samsung", "google", "espressif"]
    vendors = client_vendors or [random.choice(default_vendors) for _ in range(client_count)]
    client_macs = [make_mac_for_vendor(v) for v in vendors]

    for cmac in client_macs:
        for _ in range(2):
            packets.append(craft_probe_request(cmac, ssid, rssi_dbm - random.randint(5, 15)))

    # 3. EAPOL handshake if WPA2/WPA3
    if enc in ("wpa2", "wpa3") and client_macs:
        target_client = client_macs[0]
        packets.append(craft_eapol(bssid, target_client, bssid))
        packets.append(craft_eapol(target_client, bssid, bssid))
        packets.append(craft_eapol(bssid, target_client, bssid))
        packets.append(craft_eapol(target_client, bssid, bssid))

    # 4. Deauthentication frames
    if deauth_count > 0:
        target = client_macs[0] if client_macs else BROADCAST
        for _ in range(deauth_count):
            packets.append(craft_deauth(bssid, target))

    return packets


def build_profile(profile_name: str) -> Tuple[str, list]:
    """Generate predefined high-value test profiles."""
    p = profile_name.lower()
    if p in ("enterprise", "wpa3_enterprise"):
        bssid = make_mac_for_vendor("cisco")
        pkts = generate_scenario_packets(
            ssid="Corp-Secure-WPA3",
            bssid=bssid,
            channel=36,
            encryption="wpa3",
            wps=False,
            mfp="required",
            deauth_count=0,
            client_count=3,
            client_vendors=["apple", "intel", "cisco"],
            rssi_dbm=-48,
        )
        return "corporate_wpa3_enterprise.pcapng", pkts

    elif p in ("evil-twin", "evil_twin", "rogue_ap"):
        legit_bssid = make_mac_for_vendor("cisco")
        rogue_bssid = make_random_mac(locally_administered=True)
        # Legit AP beacons
        legit_pkts = generate_scenario_packets(
            ssid="Corp-Secure-Net",
            bssid=legit_bssid,
            channel=36,
            encryption="wpa2",
            wps=False,
            mfp="capable",
            rssi_dbm=-65,
        )
        # Rogue AP beacons (Open network masquerading as Corp)
        rogue_pkts = generate_scenario_packets(
            ssid="Corp-Secure-Net",
            bssid=rogue_bssid,
            channel=6,
            encryption="open",
            wps=False,
            deauth_count=22,  # Flooding deauth to disconnect from legit AP
            client_count=2,
            client_vendors=["apple", "samsung"],
            rssi_dbm=-38,
        )
        return "rogue_evil_twin_attack.pcapng", legit_pkts + rogue_pkts

    elif p in ("iot", "smarthome"):
        bssid = make_mac_for_vendor("netgear")
        pkts = generate_scenario_packets(
            ssid="SmartHome-IoT-Hub",
            bssid=bssid,
            channel=11,
            encryption="tkip",
            wps=True,
            mfp="none",
            deauth_count=0,
            client_count=3,
            client_vendors=["espressif", "rpi", "amazon"],
            rssi_dbm=-58,
        )
        return "iot_smarthome_legacy.pcapng", pkts

    elif p in ("cafe", "public", "coffee_shop"):
        bssid = make_mac_for_vendor("tplink")
        pkts = generate_scenario_packets(
            ssid="Starbucks_Free_WiFi",
            bssid=bssid,
            channel=1,
            encryption="open",
            wps=False,
            deauth_count=0,
            client_count=5,
            client_vendors=["apple", "google", "samsung", "apple", "samsung"],
            rssi_dbm=-52,
        )
        # Add random probe requests from mobile phones
        for _ in range(6):
            rand_mac = make_random_mac(locally_administered=True)
            pkts.append(craft_probe_request(rand_mac, random.choice(["HomeNet", "OfficeGuest", "AirportWiFi"])))
        return "public_cafe_cleartext.pcapng", pkts

    elif p in ("dos-elevated", "dos_elevated"):
        bssid = make_mac_for_vendor("samsung")
        pkts = generate_scenario_packets(
            ssid="BranchOffice_WLAN",
            bssid=bssid,
            channel=6,
            encryption="wpa2",
            wps=False,
            mfp="capable",
            deauth_count=6,  # 6 deauths -> Triggers DOS-002 (3-9 frames), not DOS-001 (>=10)
            client_count=2,
            client_vendors=["samsung", "apple"],
            rssi_dbm=-55,
        )
        return "elevated_dos_anomalies.pcapng", pkts

    elif p in ("wep", "legacy_wep"):
        bssid = make_mac_for_vendor("cisco")
        pkts = generate_scenario_packets(
            ssid="Legacy-Warehouse-Scanners",
            bssid=bssid,
            channel=3,
            encryption="wep",
            wps=False,
            deauth_count=0,
            client_count=2,
            client_vendors=["intel", "cisco"],
            rssi_dbm=-68,
        )
        return "legacy_wep_warehouse.pcapng", pkts

    elif p in ("multi-ap", "campus"):
        bssid1 = make_mac_for_vendor("cisco")
        bssid2 = make_mac_for_vendor("netgear")
        bssid3 = make_mac_for_vendor("tplink")
        pkts1 = generate_scenario_packets("Campus-WPA3-Secure", bssid1, channel=36, encryption="wpa3", mfp="required")
        pkts2 = generate_scenario_packets("Campus-Public-Guest", bssid2, channel=6, encryption="open")
        pkts3 = generate_scenario_packets("Campus-Staff-WPA2", bssid3, channel=1, encryption="wpa2", wps=True, deauth_count=12)
        return "university_campus_mixed.pcapng", pkts1 + pkts2 + pkts3

    else:
        raise ValueError(f"Unknown profile: {profile_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate custom or randomized 802.11 PCAP files for Wireless Security Assessment."
    )
    parser.add_argument("--profile", choices=["enterprise", "evil-twin", "iot", "cafe", "dos-elevated", "wep", "multi-ap", "all"],
                        help="Generate a specific threat profile")
    parser.add_argument("--random", action="store_true", help="Generate a unique random network scenario every run")
    parser.add_argument("--ssid", type=str, default=None, help="Custom SSID network name")
    parser.add_argument("--vendor", type=str, choices=list(VENDOR_OUIS.keys()), default="cisco", help="AP Hardware Vendor OUI")
    parser.add_argument("--channel", type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48], default=6, help="802.11 Wi-Fi channel")
    parser.add_argument("--encryption", choices=["open", "wep", "tkip", "wpa2", "wpa3", "mixed"], default="wpa2", help="Encryption standard")
    parser.add_argument("--wps", action="store_true", help="Enable WPS advertisement (AUTH-001)")
    parser.add_argument("--mfp", choices=["none", "capable", "required"], default="capable", help="Management Frame Protection 802.11w")
    parser.add_argument("--deauth", type=int, default=0, help="Number of deauth frames to inject (0=none, 5=DOS-002, 15=DOS-001)")
    parser.add_argument("--clients", type=int, default=3, help="Number of client stations to simulate")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output destination file (.pcapng)")

    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    simulated_dir = project_root / "data" / "simulated"
    samples_dir = project_root / "data" / "samples"
    simulated_dir.mkdir(parents=True, exist_ok=True)
    samples_dir.mkdir(parents=True, exist_ok=True)

    if args.profile == "all":
        profiles = ["enterprise", "evil-twin", "iot", "cafe", "dos-elevated", "wep", "multi-ap"]
        print(f"[*] Generating {len(profiles)} threat scenario captures into data/simulated/ and data/samples/...")
        for prof in profiles:
            filename, pkts = build_profile(prof)
            path1 = simulated_dir / filename
            path2 = samples_dir / filename
            wrpcap(str(path1), pkts)
            wrpcap(str(path2), pkts)
            print(f"  [+] Created {filename:35s} ({len(pkts):3d} packets)")
        print("[✓] All sample captures successfully generated!")
        return

    if args.profile:
        filename, pkts = build_profile(args.profile)
        out_path = Path(args.output) if args.output else (simulated_dir / filename)
        wrpcap(str(out_path), pkts)
        print(f"[✓] Generated profile '{args.profile}' -> {out_path} ({len(pkts)} packets)")
        return

    if args.random:
        adjectives = ["Omega", "Hyper", "Apex", "Cyber", "Quantum", "Orbit", "Nova", "Flux", "Echo"]
        nouns = ["HQ", "Net", "Air", "Link", "Core", "Mesh", "Portal", "Lab", "Zone"]
        random_ssid = f"{random.choice(adjectives)}_{random.choice(nouns)}_{random.randint(10, 99)}"
        random_vendor = random.choice(list(VENDOR_OUIS.keys()))
        bssid = make_mac_for_vendor(random_vendor)
        channel = random.choice([1, 6, 11, 36, 44])
        enc = random.choice(["open", "wep", "tkip", "wpa2", "wpa3"])
        wps = random.choice([True, False]) if enc in ("wpa2", "tkip") else False
        mfp = random.choice(["none", "capable", "required"]) if enc in ("wpa2", "wpa3") else "none"
        deauth = random.choice([0, 0, 5, 18])
        clients = random.randint(2, 6)

        pkts = generate_scenario_packets(
            ssid=random_ssid,
            bssid=bssid,
            channel=channel,
            encryption=enc,
            wps=wps,
            mfp=mfp,
            deauth_count=deauth,
            client_count=clients,
            rssi_dbm=random.randint(-75, -40),
        )

        out_name = f"dynamic_{random_ssid.lower()}.pcapng"
        out_path = Path(args.output) if args.output else (simulated_dir / out_name)
        wrpcap(str(out_path), pkts)

        print("\n" + "=" * 60)
        print("  DYNAMIC SAMPLE PCAP GENERATED (NON-STATIC INPUT)")
        print("=" * 60)
        print(f"  Output File : {out_path}")
        print(f"  SSID        : {random_ssid}")
        print(f"  BSSID       : {bssid} (Vendor: {random_vendor.upper()})")
        print(f"  Channel     : {channel}")
        print(f"  Encryption  : {enc.upper()}")
        print(f"  WPS         : {'Enabled (Vulnerable)' if wps else 'Disabled'}")
        print(f"  MFP 802.11w : {mfp.upper()}")
        print(f"  Deauth Pkts : {deauth}")
        print(f"  Clients     : {clients}")
        print(f"  Total Pkts  : {len(pkts)}")
        print("=" * 60 + "\n")
        return

    # Custom mode
    custom_ssid = args.ssid or f"CustomAP_{random.randint(100, 999)}"
    bssid = make_mac_for_vendor(args.vendor)
    pkts = generate_scenario_packets(
        ssid=custom_ssid,
        bssid=bssid,
        channel=args.channel,
        encryption=args.encryption,
        wps=args.wps,
        mfp=args.mfp,
        deauth_count=args.deauth,
        client_count=args.clients,
    )
    out_name = f"custom_{custom_ssid.lower().replace(' ', '_')}.pcapng"
    out_path = Path(args.output) if args.output else (simulated_dir / out_name)
    wrpcap(str(out_path), pkts)

    print("\n" + "=" * 60)
    print("  CUSTOM WIRELESS PCAP GENERATED")
    print("=" * 60)
    print(f"  Output File : {out_path}")
    print(f"  SSID        : {custom_ssid}")
    print(f"  BSSID       : {bssid} ({args.vendor.upper()})")
    print(f"  Channel     : {args.channel}")
    print(f"  Encryption  : {args.encryption.upper()}")
    print(f"  WPS         : {'Enabled' if args.wps else 'Disabled'}")
    print(f"  MFP 802.11w : {args.mfp.upper()}")
    print(f"  Deauth Pkts : {args.deauth}")
    print(f"  Clients     : {args.clients}")
    print(f"  Total Pkts  : {len(pkts)}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
