# Wireless Network Security Assessment (WSA Kali)

**WSA** is an integrated, professional wireless network security assessment and operations platform designed for Kali Linux. It combines the core defensive auditing capabilities of **Aircrack-ng**, **Airmon-ng**, **Airodump-ng**, and **Wireshark** into a unified, user-friendly platform.

WSA supports both **live assessment** (when a compatible Wi-Fi adapter or virtual interface is present) and **adapter-independent offline assessment** (working smoothly via uploaded PCAP/PCAPNG files and offline simulation playback even when `wlan0` or physical wireless hardware is unavailable).

---

## Key Features & Capabilities

1. **Integrated Kali Wireless Suite:**
   - **Airmon-ng Engine:** Monitor mode detection, interface diagnostics, virtual lab capability checks (`mac80211_hwsim`), and adapter health.
   - **Airodump-ng Discovery:** Passive detection of nearby APs, SSID, BSSID, channel, signal strength (RSSI), beacon rates, encryption standards, and client station tracking.
   - **Wireshark Deep Packet Inspection:** 802.11 frame category breakdown (Management, Control, Data, EAPOL handshakes), channel occupancy distribution, and interactive packet inspector table.
   - **Aircrack-ng Audit & Risk Scorer:** Comprehensive evaluation of wireless standards (**Open**, **WEP**, **WPA**, **WPA2-CCMP**, **WPA3-SAE**, **OWE**), finding classification (Critical, High, Medium, Low, Info), and technical remediation roadmaps.

2. **Dual-Mode Operation (Live & Adapter-Independent Offline):**
   - **Live Assessment:** Incremental Scapy capture (`sniff`) on any monitor mode interface (`wlan0mon`, `hwsim0`, Alfa adapters) with real-time SSE streaming.
   - **Adapter-Independent Offline Mode:** Operates even when physical wireless cards or `wlan0` are absent. Analyzes uploaded PCAPs and provides an offline simulation playback mode with six threat profiles for IDS testing without hardware.

3. **Vulnerability Assessment & Threat Detection:**
   - Detects plaintext open networks, deprecated WEP encryption, and TKIP cipher suites.
   - Flags Wi-Fi Protected Setup (WPS) PIN exposure vulnerabilities (Pixie Dust / brute-force risk).
   - Identifies missing or optional 802.11w Management Frame Protection (MFP).
   - Detects active deauthentication/disassociation flooding anomalies in real time.

4. **Before-and-After Security Comparison (Stage 5):**
   - Side-by-side comparison between any two assessment sessions (baseline vs target).
   - Computes risk score delta (+/- points and % change) with posture verdict (`IMPROVED`, `REGRESSED`, `UNCHANGED`).
   - Categorizes findings into **Resolved** (remediated vulnerabilities), **New** (regressions), and **Persistent**.
   - Pinpoints per-network configuration changes (e.g., WEP → CCMP, WPS disabled, MFP enforced).

5. **Device Identification & Station Tracking:**
   - Tracks client station MAC addresses, AP associations, and unassociated probe requests.
   - Resolves hardware vendor/manufacturer via IEEE OUI lookup (Apple, Intel, Samsung, Espressif, Raspberry Pi, etc.).
   - Detects IEEE 802 randomized/locally-administered MAC privacy addresses.
   - Flags station-specific threat indicators (e.g., targeted by deauth frames, connected to unencrypted APs).

6. **Audit-Grade Multi-Format Reports:**
   - **PDF:** Executive multi-page PDF report with cover, risk gauge, networks table, and remediation roadmaps (via ReportLab).
   - **HTML:** Standalone, zero-dependency responsive HTML report with embedded styles for offline presentation.
   - **JSON:** Schema-versioned machine-readable dataset for SIEM, Splunk, or automated CI pipelines.
   - **Markdown:** GitHub-Flavored Markdown report for technical wikis and documentation.

---

## Architecture Overview

- `wsa/ingestion/`: Scapy packet reading (`pcap_reader.py`) and 802.11 frame classification (`frame_parser.py`).
- `wsa/analysis/`: Beacon feature extraction (`beacon_extractor.py`), client station & OUI vendor tracking (`device_tracker.py`), and deep packet inspection (`protocol_analyzer.py`).
- `wsa/rules/`: Extensible YAML rule engine (`engine.py`, `evaluator.py`, `loader.py`) evaluating encryption, authentication, and DoS indicators.
- `wsa/comparison/`: Differential audit engine (`comparator.py`) computing before-and-after posture deltas.
- `wsa/reporting/`: Assessment models (`assessment.py`), PDF generator (`pdf_reporter.py`), HTML reporter (`html_reporter.py`), JSON reporter (`json_reporter.py`), and Markdown reporter (`markdown_reporter.py`).
- `wsa/api/`: Standard-library HTTP server (`server.py`), storage manager (`storage.py`), diagnostics, and live capture service (`live_lab.py`).
- `frontend/`: Modern React/Vite dashboard styled with a dark Kali Linux SOC theme.

---

## Installation & Setup

1. **Install Python and Node dependencies:**
   ```bash
   python -m venv .venv
   .venv/bin/pip install -e ".[dev]"
   cd frontend
   npm install
   cd ..
   ```

2. **Start the application:**
   ```bash
   ./start-wsa.sh
   ```
   Or launch manually in two terminals:
   ```bash
   # Terminal 1: Backend API
   .venv/bin/python -m wsa.api

   # Terminal 2: Frontend Dashboard
   cd frontend
   npm run dev
   ```
   Open `http://localhost:5173` in your browser.

3. **Run diagnostics:**
   ```bash
   ./start-wsa.sh --diagnose
   ```

4. **Stop the application:**
   ```bash
   ./stop-wsa.sh
   ```

---

## Testing & Verification

Run the comprehensive unit and integration test suite:
```bash
.venv/bin/pytest
cd frontend && npm run build
```

---

## Ethical Use & Defensive Policy

WSA is designed exclusively for authorized wireless security assessments, defensive network hardening, compliance validation, and educational cybersecurity labs. WSA strictly captures and monitors observed traffic passively; it never transmits unauthorized packets, executes injection attacks, or attempts unauthorized credential cracking against external networks.
