"""
Deep packet inspection and 802.11 protocol analyzer.

Provides Wireshark-like protocol breakdown, frame category statistics,
RF channel occupancy, and individual frame inspection details.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Deauth, Dot11Auth
from scapy.layers.eap import EAPOL
from scapy.packet import Packet

# Dot11 subtypes lookup table
MANAGEMENT_SUBTYPES = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    9: "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
    14: "Action No Ack",
}

CONTROL_SUBTYPES = {
    4: "Beamforming Report Poll",
    5: "VHT/HE NDP Announcement",
    7: "Control Wrapper",
    8: "Block ACK Request",
    9: "Block ACK",
    10: "PS-Poll",
    11: "RTS",
    12: "CTS",
    13: "ACK",
    14: "CF-End",
    15: "CF-End + CF-Ack",
}

DATA_SUBTYPES = {
    0: "Data",
    1: "Data + CF-Ack",
    2: "Data + CF-Poll",
    3: "Data + CF-Ack + CF-Poll",
    4: "Null Data",
    5: "CF-Ack",
    6: "CF-Poll",
    7: "CF-Ack + CF-Poll",
    8: "QoS Data",
    9: "QoS Data + CF-Ack",
    10: "QoS Data + CF-Poll",
    11: "QoS Data + CF-Ack + CF-Poll",
    12: "QoS Null",
    14: "QoS CF-Poll",
    15: "QoS CF-Ack + CF-Poll",
}

_LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"


def analyze_protocol_and_packets(packets: List[Packet], sample_limit: int = 75) -> Dict[str, Any]:
    """
    Perform deep packet inspection and protocol analysis over captured packets.
    """
    total = len(packets)
    if total == 0:
        return {
            "total_packets": 0,
            "categories": {"management": 0, "control": 0, "data": 0, "unknown": 0},
            "subtypes": {},
            "channels": {},
            "samples": [],
        }

    categories = {"management": 0, "control": 0, "data": 0, "unknown": 0}
    subtype_counts: Dict[str, int] = {}
    channel_counts: Dict[str, int] = {}
    rssi_values: List[int] = []
    eapol_count = 0
    samples: List[Dict[str, Any]] = []

    for idx, pkt in enumerate(packets):
        # Channel / RSSI from RadioTap
        channel_str = "Unknown"
        rssi_val = None
        if pkt.haslayer("RadioTap"):
            rt = pkt.getlayer("RadioTap")
            rssi = getattr(rt, "dBm_AntSignal", None)
            if rssi is not None:
                rssi_values.append(int(rssi))
                rssi_val = int(rssi)
            # Channel extraction
            ch = getattr(rt, "Channel", None)
            if ch is not None:
                try:
                    # ch can be frequency e.g. 2412 or channel number
                    freq = int(ch) if isinstance(ch, (int, str)) else 0
                    if 2412 <= freq <= 2484:
                        ch_num = 14 if freq == 2484 else (freq - 2407) // 5
                        channel_str = f"Ch {ch_num} ({freq} MHz)"
                    elif 5170 <= freq <= 5825:
                        ch_num = (freq - 5000) // 5
                        channel_str = f"Ch {ch_num} ({freq} MHz)"
                    else:
                        channel_str = f"Ch {freq}"
                except Exception:
                    channel_str = str(ch)

        if not pkt.haslayer(Dot11):
            categories["unknown"] += 1
            if len(samples) < sample_limit:
                samples.append({
                    "id": idx + 1,
                    "type": "Non-802.11",
                    "subtype": pkt.name,
                    "source": "N/A",
                    "destination": "N/A",
                    "bssid": "N/A",
                    "length": len(pkt),
                    "channel": channel_str,
                    "rssi": rssi_val,
                    "info": pkt.summary()[:120],
                })
            continue

        dot11 = pkt[Dot11]
        f_type = dot11.type
        f_subtype = dot11.subtype

        addr1 = getattr(dot11, "addr1", "") or "ff:ff:ff:ff:ff:ff"
        addr2 = getattr(dot11, "addr2", "") or "N/A"
        addr3 = getattr(dot11, "addr3", "") or "N/A"

        # Check for EAPOL
        is_eapol = False
        if pkt.haslayer(EAPOL):
            is_eapol = True
        elif pkt.haslayer("Raw"):
            raw_bytes = bytes(pkt["Raw"].load)
            if len(raw_bytes) >= len(_LLC_SNAP_EAPOL) and raw_bytes[:len(_LLC_SNAP_EAPOL)] == _LLC_SNAP_EAPOL:
                is_eapol = True
        if is_eapol:
            eapol_count += 1

        type_name = "Unknown"
        subtype_name = "Unknown"

        if f_type == 0:
            categories["management"] += 1
            type_name = "Management"
            subtype_name = MANAGEMENT_SUBTYPES.get(f_subtype, f"Management Subtype {f_subtype}")
        elif f_type == 1:
            categories["control"] += 1
            type_name = "Control"
            subtype_name = CONTROL_SUBTYPES.get(f_subtype, f"Control Subtype {f_subtype}")
        elif f_type == 2:
            categories["data"] += 1
            type_name = "Data"
            if is_eapol:
                subtype_name = "EAPOL (Key Exchange / Handshake)"
            else:
                subtype_name = DATA_SUBTYPES.get(f_subtype, f"Data Subtype {f_subtype}")
        else:
            categories["unknown"] += 1
            type_name = f"Reserved ({f_type})"
            subtype_name = f"Subtype {f_subtype}"

        subtype_counts[subtype_name] = subtype_counts.get(subtype_name, 0) + 1
        if channel_str != "Unknown":
            channel_counts[channel_str] = channel_counts.get(channel_str, 0) + 1

        if len(samples) < sample_limit:
            info_summary = pkt.summary()
            if pkt.haslayer(Dot11Beacon):
                try:
                    from scapy.layers.dot11 import Dot11Elt
                    elt = pkt.getlayer(Dot11Elt)
                    ssid_val = ""
                    while elt:
                        if getattr(elt, "ID", -1) == 0 and getattr(elt, "info", None):
                            ssid_val = elt.info.decode("utf-8", errors="replace")
                            break
                        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
                    if ssid_val:
                        info_summary = f"Beacon: SSID={ssid_val!r} BSSID={addr3}"
                except Exception:
                    pass

            samples.append({
                "id": idx + 1,
                "type": type_name,
                "subtype": subtype_name,
                "source": addr2,
                "destination": addr1,
                "bssid": addr3,
                "length": len(pkt),
                "channel": channel_str,
                "rssi": rssi_val,
                "info": info_summary[:120],
            })

    # Sort channels by count
    sorted_channels = dict(sorted(channel_counts.items(), key=lambda item: item[1], reverse=True))
    sorted_subtypes = dict(sorted(subtype_counts.items(), key=lambda item: item[1], reverse=True))

    return {
        "total_packets": total,
        "categories": categories,
        "subtypes": sorted_subtypes,
        "channels": sorted_channels,
        "eapol_frames": eapol_count,
        "avg_rssi": round(sum(rssi_values) / len(rssi_values), 1) if rssi_values else None,
        "min_rssi": min(rssi_values) if rssi_values else None,
        "max_rssi": max(rssi_values) if rssi_values else None,
        "samples": samples,
    }
