# 📡 Real Wireless Captures

This directory is a **placeholder** for PCAP files captured from a real
Wi-Fi adapter in monitor mode.  No sample files are included in the
repository — you must supply your own.

> [!NOTE]
> A physical Wi-Fi adapter with monitor-mode support is required.
> The project's analysis engine is identical for real and simulated data;
> only the `data_source` label in the report changes.

---

## Capture Instructions

### Using airodump-ng (aircrack-ng suite)
```bash
sudo airmon-ng start wlan0                       # enable monitor mode
sudo airodump-ng -w capture --output-format pcapng wlan0mon
# Press Ctrl+C when done
```

### Using Wireshark
```
1. Select your Wi-Fi interface
2. Enable monitor mode in Interface Options
3. Start capture → File → Export Specified Packets → .pcapng
```

### Using tcpdump
```bash
sudo tcpdump -i wlan0mon -w capture.pcapng type mgt
```

---

## Analysis

```bash
python wsa.py analyze data/real/your_capture.pcapng --data-source real
```

> [!CAUTION]
> Only capture traffic on networks you own or have explicit written
> permission to test.  Capturing third-party Wi-Fi traffic without
> authorisation is illegal in most jurisdictions.
