# 🔬 Simulated Test Data

> [!IMPORTANT]
> **DATA PROVENANCE — SYNTHETIC / SIMULATED**
>
> Every PCAP file in this directory is **artificially generated** using the
> [scapy](https://scapy.net) Python library.  
> They do **NOT** represent real-world wireless captures and were **NOT**
> produced by any physical Wi-Fi adapter, monitor-mode interface, or any
> active wireless operation (no scanning, no deauthentication attacks, no
> password cracking).  
> All MAC addresses are randomly generated and do not correspond to any
> real device.  
> These files exist solely to enable **offline testing and demonstration**
> on systems without Wi-Fi hardware.

---

## File Catalogue

| File | Scenario | Key Security Properties | Expected Findings |
|------|----------|------------------------|-------------------|
| `open_network.pcapng` | Open café AP | No encryption, no auth | ENC-001 CRITICAL |
| `wep_network.pcapng` | Legacy corporate AP | WEP-only (deprecated 2004) | ENC-002 CRITICAL |
| `wpa2_personal.pcapng` | Home AP with WPS | WPA2-PSK/CCMP, MFP capable, WPS on, handshake present | AUTH-001 HIGH, MGT-001 INFO |
| `wpa3_network.pcapng` | Modern secure AP | WPA3-SAE/CCMP, MFP required | INFO only |
| `deauth_flood.pcapng` | Under attack | WPA2-PSK, no MFP, deauth flood (20 frames) | DOS-001 HIGH |
| `mixed_environment.pcapng` | Multi-AP site survey | All of the above combined | Full finding spectrum |

---

## Regenerating the Files

```bash
# Via the CLI (Stage 5+)
python wsa.py generate-samples

# Directly via the generator script
python tests/generators/generate_test_pcaps.py

# To a custom output directory
python tests/generators/generate_test_pcaps.py --output /tmp/my_samples/
```

---

## How the Frames Are Constructed

The generator crafts synthetic IEEE 802.11 management frames:

- **Beacon frames** — carry SSID, BSSID, channel, RSN Information Element  
  (cipher suites, AKM suites, RSN capabilities for MFP), and optionally a
  WPS vendor-specific IE.
- **Probe request frames** — simulate client devices broadcasting saved
  network names (directed probes).
- **EAPOL frames** — embedded in 802.11 data frames to simulate a WPA2
  4-way handshake key exchange.
- **Deauthentication frames** — simulate a deauth flood from a spoofed
  source MAC (no real deauth attack is performed).

All frames are written with a [RadioTap](https://www.radiotap.org/) header
so they load cleanly in Wireshark and scapy.

---

## Verification

```python
from scapy.all import rdpcap
pkts = rdpcap("data/simulated/mixed_environment.pcapng")
print(f"Loaded {len(pkts)} frames")
```
