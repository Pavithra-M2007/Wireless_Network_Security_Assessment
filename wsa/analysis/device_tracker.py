"""
Device and station tracking for 802.11 wireless assessments.

Identifies client stations, resolves OUI manufacturers, tracks AP associations,
inspects probed networks, and flags client-specific security threats.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Deauth, Dot11Beacon
from scapy.packet import Packet

# Dot11Disas exists in scapy 2.5+
try:
    from scapy.layers.dot11 import Dot11Disas
    _HAVE_DISAS = True
except ImportError:
    _HAVE_DISAS = False

# Common OUI prefix mapping (first 3 octets, lower-case, colon-separated)
OUI_DATABASE: Dict[str, str] = {
    "00:0c:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "00:05:69": "VMware, Inc.",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "08:00:27": "Oracle VirtualBox",
    "f0:18:98": "Apple, Inc.",
    "3c:22:fb": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.",
    "f8:ff:c2": "Apple, Inc.",
    "a4:83:e7": "Apple, Inc.",
    "28:cf:e9": "Apple, Inc.",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Foundation",
    "00:1a:11": "Google, Inc.",
    "3c:5a:37": "Google, Inc.",
    "d4:f5:47": "Google, Inc.",
    "00:1e:67": "Intel Corporate",
    "00:21:6a": "Intel Corporate",
    "00:16:ea": "Intel Corporate",
    "00:1f:3b": "Intel Corporate",
    "00:1c:bf": "Intel Corporate",
    "60:f2:62": "Intel Corporate",
    "00:1a:2b": "Cisco Systems",
    "00:26:08": "Cisco Systems",
    "00:14:bf": "Cisco-Linksys",
    "00:18:39": "Cisco-Linksys",
    "00:25:9c": "Cisco-Linksys",
    "00:19:e0": "TP-Link Technologies",
    "50:c7:bf": "TP-Link Technologies",
    "ec:08:6b": "TP-Link Technologies",
    "98:48:27": "TP-Link Technologies",
    "24:0a:c4": "Espressif Systems",
    "30:ae:a4": "Espressif Systems",
    "84:f3:eb": "Espressif Systems",
    "a0:20:a6": "Espressif Systems",
    "00:24:81": "Netgear, Inc.",
    "00:26:f2": "Netgear, Inc.",
    "20:4e:7f": "Netgear, Inc.",
    "00:15:af": "Samsung Electronics",
    "00:16:32": "Samsung Electronics",
    "00:17:c9": "Samsung Electronics",
    "34:23:87": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "00:13:a9": "Sony Corporation",
    "00:1b:dc": "Sony Corporation",
    "00:1e:8c": "ASUSTek Computer",
    "00:1f:c6": "ASUSTek Computer",
    "00:24:01": "D-Link Corporation",
    "00:26:5a": "D-Link Corporation",
    "00:04:4b": "Nvidia Corporation",
    "00:09:bf": "Nintendo Co., Ltd.",
    "00:1f:33": "Netgear",
    "70:4f:57": "Amazon Technologies",
    "f0:27:2d": "Amazon Technologies",
    "00:12:17": "Cisco Systems",
    "00:11:22": "Croma / Test OUI",
    "02:00:00": "Locally Administered",
}


def is_locally_administered(mac: str) -> bool:
    """Return True if the MAC address has the IEEE 802 locally-administered bit set."""
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


def resolve_vendor(mac: str) -> str:
    """Resolve an OUI vendor string from a MAC address."""
    clean = mac.lower().strip()
    if is_locally_administered(clean):
        return "Randomized / Private MAC (Privacy Feature)"
    prefix = clean[:8]
    if prefix in OUI_DATABASE:
        return OUI_DATABASE[prefix]
    return "Unknown Vendor (Unregistered OUI)"


@dataclass
class TrackedStation:
    """A wireless client station or peripheral discovered during capture."""
    mac: str
    vendor: str
    is_randomized: bool = False
    associated_bssid: Optional[str] = None
    associated_ssid: Optional[str] = None
    probed_ssids: List[str] = field(default_factory=list)
    frame_count: int = 0
    deauth_count: int = 0
    rssi_readings: List[int] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)

    @property
    def avg_rssi_dbm(self) -> Optional[float]:
        return sum(self.rssi_readings) / len(self.rssi_readings) if self.rssi_readings else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac,
            "vendor": self.vendor,
            "is_randomized": self.is_randomized,
            "associated_bssid": self.associated_bssid,
            "associated_ssid": self.associated_ssid,
            "probed_ssids": sorted(list(set(self.probed_ssids))),
            "frame_count": self.frame_count,
            "deauth_count": self.deauth_count,
            "avg_rssi_dbm": round(self.avg_rssi_dbm, 1) if self.avg_rssi_dbm is not None else None,
            "threat_indicators": list(dict.fromkeys(self.threat_indicators)),
        }


def extract_stations(packets: List[Packet], known_networks: Optional[List[Any]] = None) -> List[TrackedStation]:
    """
    Extract wireless client stations and associated details from 802.11 frames.

    Excludes AP BSSIDs, broadcast (ff:ff:ff:ff:ff:ff), and multicast MACs.
    """
    known_bssids: Set[str] = set()
    bssid_to_ssid: Dict[str, str] = {}
    bssid_to_cipher: Dict[str, str] = {}

    if known_networks:
        for net in known_networks:
            bssid = getattr(net, "bssid", None)
            if bssid:
                clean_bssid = bssid.lower()
                known_bssids.add(clean_bssid)
                ssid = getattr(net, "ssid", None)
                if ssid:
                    bssid_to_ssid[clean_bssid] = ssid
                cipher = getattr(net, "cipher", None)
                if cipher:
                    bssid_to_cipher[clean_bssid] = cipher

    # Also detect AP BSSIDs directly from beacons in the packet list
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11):
            ap_mac = getattr(pkt[Dot11], "addr3", None) or getattr(pkt[Dot11], "addr2", None)
            if ap_mac:
                known_bssids.add(ap_mac.lower())

    stations: Dict[str, TrackedStation] = {}
    invalid_addrs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", ""}

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        addr1 = (getattr(dot11, "addr1", "") or "").lower()
        addr2 = (getattr(dot11, "addr2", "") or "").lower()
        addr3 = (getattr(dot11, "addr3", "") or "").lower()

        # Extract RadioTap RSSI if available
        rssi = None
        if pkt.haslayer("RadioTap"):
            rt = pkt.getlayer("RadioTap")
            rssi = getattr(rt, "dBm_AntSignal", None)

        # 1. Inspect Probe Requests
        if pkt.haslayer(Dot11ProbeReq):
            client_mac = addr2
            if client_mac and client_mac not in invalid_addrs and client_mac not in known_bssids:
                if client_mac not in stations:
                    stations[client_mac] = TrackedStation(
                        mac=client_mac,
                        vendor=resolve_vendor(client_mac),
                        is_randomized=is_locally_administered(client_mac),
                    )
                st = stations[client_mac]
                st.frame_count += 1
                if rssi is not None:
                    st.rssi_readings.append(rssi)

                # Extract probed SSID
                layer = pkt[Dot11ProbeReq].payload
                while layer and layer.name != "NoPayload":
                    if getattr(layer, "ID", -1) == 0:
                        info = bytes(layer.info) if layer.info else b""
                        if info and info.strip(b"\x00"):
                            st.probed_ssids.append(info.decode("utf-8", errors="replace"))
                        break
                    layer = layer.payload
            continue

        # 2. Inspect Deauth / Disassociation frames
        is_deauth = False
        if pkt.haslayer(Dot11Deauth):
            is_deauth = True
        elif _HAVE_DISAS and pkt.haslayer(Dot11Disas):
            is_deauth = True
        elif dot11.type == 0 and dot11.subtype in (10, 12):
            is_deauth = True

        if is_deauth:
            # addr1 is victim, addr2 is transmitter, addr3 is BSSID
            victim = addr1
            if victim and victim not in invalid_addrs and victim not in known_bssids:
                if victim not in stations:
                    stations[victim] = TrackedStation(
                        mac=victim,
                        vendor=resolve_vendor(victim),
                        is_randomized=is_locally_administered(victim),
                    )
                st = stations[victim]
                st.deauth_count += 1
                st.frame_count += 1
                st.threat_indicators.append("Targeted by Deauthentication / Disassociation frames")
                if addr3 in known_bssids and not st.associated_bssid:
                    st.associated_bssid = addr3
                    st.associated_ssid = bssid_to_ssid.get(addr3)

        # 3. Inspect Data / Management frame associations
        # Check if addr2 is client sending to AP (addr1 or addr3)
        if addr2 and addr2 not in invalid_addrs and addr2 not in known_bssids:
            if addr2 not in stations:
                stations[addr2] = TrackedStation(
                    mac=addr2,
                    vendor=resolve_vendor(addr2),
                    is_randomized=is_locally_administered(addr2),
                )
            st = stations[addr2]
            st.frame_count += 1
            if rssi is not None:
                st.rssi_readings.append(rssi)
            target_ap = addr1 if addr1 in known_bssids else (addr3 if addr3 in known_bssids else None)
            if target_ap and not st.associated_bssid:
                st.associated_bssid = target_ap
                st.associated_ssid = bssid_to_ssid.get(target_ap)

        # Check if addr1 is client receiving from AP (addr2 or addr3)
        if addr1 and addr1 not in invalid_addrs and addr1 not in known_bssids:
            if addr1 not in stations:
                stations[addr1] = TrackedStation(
                    mac=addr1,
                    vendor=resolve_vendor(addr1),
                    is_randomized=is_locally_administered(addr1),
                )
            st = stations[addr1]
            st.frame_count += 1
            source_ap = addr2 if addr2 in known_bssids else (addr3 if addr3 in known_bssids else None)
            if source_ap and not st.associated_bssid:
                st.associated_bssid = source_ap
                st.associated_ssid = bssid_to_ssid.get(source_ap)

    # Post-process threat indicators
    for st in stations.values():
        if st.associated_bssid:
            cipher = bssid_to_cipher.get(st.associated_bssid, "")
            if cipher in ("NONE", "WEP"):
                st.threat_indicators.append(f"Associated with insecure {cipher} wireless network")
        if st.deauth_count >= 5:
            st.threat_indicators.append(f"High deauthentication flood victim ({st.deauth_count} frames)")

    return sorted(list(stations.values()), key=lambda s: s.frame_count, reverse=True)
