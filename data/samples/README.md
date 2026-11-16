# Sample Wireless PCAP Input Captures & Dynamic Input Guide

This directory contains diverse IEEE 802.11 wireless capture files (`.pcapng`) designed to replace static values with varying network topologies, threat indicators, client distributions, and security standards.

---

## 1. Pre-built Sample Capture Files

All sample captures are available in [`data/samples/`](file:///home/pavi/wireless-security-assessment/data/samples) and [`data/simulated/`](file:///home/pavi/wireless-security-assessment/data/simulated).

| File Name | Primary Scenario | SSID & Channel | AP Vendor | Encryption / Security | Expected Findings | Overall Risk Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`corporate_wpa3_enterprise.pcapng`** | Hardened Corporate AP | `Corp-Secure-WPA3` (Ch 36) | Cisco Systems | WPA3-Personal (SAE) + 802.11w MFP Required | *None* (Clean baseline) | **0 (SECURE)** |
| **`rogue_evil_twin_attack.pcapng`** | Evil Twin + Deauth Attack | `Corp-Secure-Net` (Ch 36 & Ch 6) | Spoofed Private / Cisco | Legit: WPA2-CCMP<br>Rogue: Open Plaintext + 22 Deauth Frames | `ENC-001` (Critical)<br>`DOS-001` (High)<br>`AUTH-003` (Low) | **57 (HIGH RISK)** |
| **`iot_smarthome_legacy.pcapng`** | IoT Hub Vulnerabilities | `SmartHome-IoT-Hub` (Ch 11) | Netgear | TKIP-Only + WPS Enabled + No 802.11w MFP | `ENC-003` (High)<br>`AUTH-001` (High)<br>`AUTH-002` (Medium) | **35 (HIGH RISK)** |
| **`public_cafe_cleartext.pcapng`** | Unencrypted Public Wi-Fi | `Starbucks_Free_WiFi` (Ch 1) | TP-Link | Open (Plaintext) + Client Probes with Randomized MACs | `ENC-001` (Critical) | **40 (CRITICAL)** |
| **`elevated_dos_anomalies.pcapng`** | Heuristic Medium DoS | `BranchOffice_WLAN` (Ch 6) | Samsung Electronics | WPA2-Personal (CCMP) + 6 Deauth frames (range 3-9) | `DOS-002` (Medium)<br>`AUTH-003` (Low) | **7 (LOW RISK)** |
| **`legacy_wep_warehouse.pcapng`** | Broken Legacy Encryption | `Legacy-Warehouse-Scanners` (Ch 3) | Cisco Systems | Deprecated WEP (64/128-bit) | `ENC-002` (Critical) | **40 (CRITICAL)** |
| **`university_campus_mixed.pcapng`** | Multi-AP Campus Environment | 3 Networks (Ch 1, 6, 36) | Cisco, Netgear, TP-Link | WPA3, Open Guest, WPA2+WPS+Deauth Flood | `ENC-001`, `DOS-001`, `AUTH-001`, `AUTH-003` | **72 (CRITICAL)** |

---

## 2. Generating Non-Static Dynamic Inputs

To prevent static values and generate custom input files on the fly, use [`scripts/generate_sample_pcap.py`](file:///home/pavi/wireless-security-assessment/scripts/generate_sample_pcap.py):

### A. Pure Randomized Mode (New non-static values every execution)
Generates randomized SSIDs, MAC addresses, channels, encryption standards, and client devices every time:
```bash
.venv/bin/python scripts/generate_sample_pcap.py --random
```

### B. Custom Network Configuration
Control every parameter of the wireless input:
```bash
.venv/bin/python scripts/generate_sample_pcap.py \
    --ssid "MyOfficeMesh" \
    --vendor cisco \
    --channel 36 \
    --encryption wpa3 \
    --mfp required \
    --clients 5 \
    --output data/samples/my_custom_capture.pcapng
```

### C. Simulate an Active Deauthentication Flood
```bash
.venv/bin/python scripts/generate_sample_pcap.py \
    --ssid "TargetNetwork" \
    --vendor netgear \
    --encryption wpa2 \
    --deauth 20 \
    --output data/samples/custom_deauth_flood.pcapng
```

---

## 3. How to Use in Live Detection & Offline Assessment

### Live Detection & Simulation Playback
1. Open the dashboard at `http://localhost:5173`.
2. Navigate to **Live Monitor**.
3. Under **Scenario**, select any scenario (e.g., *Corporate WPA3 Enterprise*, *Rogue AP / Evil Twin*, *IoT Smart Home*).
4. Select **Simulation Playback** (or your hardware monitor interface `wlan0mon`) and click **Start Playback**.
5. Watch Scapy classify frames one-by-one in real time, updating the risk gauge, OUI vendors, and threat timeline.

### Offline Assessment Upload
1. Navigate to **Assessments**.
2. Click any of the **One-Click Test Data Sample chips** or click **Choose File** to upload any custom `.pcapng` generated with `scripts/generate_sample_pcap.py`.
3. Click **Analyze Capture** to review risk scoring, vendor tracking, frame inspection, and download PDF/HTML/JSON reports.
