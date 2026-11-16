"""Actual incremental wireless capture and analysis service.

The live path captures one packet at a time with Scapy, classifies it using
the existing ingestion code, updates state, and evaluates the existing rules.
Supports both real wireless interface monitoring and adapter-independent offline playback.
"""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from wsa.analysis.feature_set import NetworkFeatures, ScanFeatures
from wsa.reporting.assessment import RISK_SCORES, Assessment, NetworkAssessment, build_assessment
from wsa.reporting.json_reporter import _na_to_dict
from wsa.rules.engine import RuleEngine

SCENARIOS = {
    "normal": "Normal Wireless Activity",
    "open": "Open Network Detection",
    "wep": "WEP Weakness",
    "auth": "Authentication Anomaly",
    "deauth": "Deauthentication / DoS Observation",
    "mixed": "Mixed Wireless Environment",
    "enterprise": "Corporate WPA3 Enterprise (Secure Baseline)",
    "evil_twin": "Rogue AP / Evil Twin & Deauth Attack",
    "iot": "IoT Smart Home (TKIP & WPS Vulnerable)",
    "cafe": "Public Cafe Cleartext & Station Probes",
    "dos_elevated": "Elevated Deauth Frame Anomaly",
    "campus": "University Campus Multi-AP Environment",
}

SCENARIO_PCAPS = {
    "normal": "mixed_environment.pcapng",
    "open": "open_network.pcapng",
    "wep": "wep_network.pcapng",
    "auth": "wpa2_personal.pcapng",
    "deauth": "deauth_flood.pcapng",
    "mixed": "mixed_environment.pcapng",
    "enterprise": "corporate_wpa3_enterprise.pcapng",
    "evil_twin": "rogue_evil_twin_attack.pcapng",
    "iot": "iot_smarthome_legacy.pcapng",
    "cafe": "public_cafe_cleartext.pcapng",
    "dos_elevated": "elevated_dos_anomalies.pcapng",
    "campus": "university_campus_mixed.pcapng",
}


def _run(command: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def _parse_iw_interfaces(output: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface "):
            if current:
                items.append(current)
            current = {"name": stripped.split()[1], "type": "unknown"}
        elif current and stripped.startswith("type "):
            current["type"] = stripped.split()[1]
    if current:
        items.append(current)
    return items


def diagnostics() -> dict[str, Any]:
    """Return truthful host/capture capability diagnostics."""
    kernel = os.uname()
    mod_code, mod_out, mod_err = _run(["modinfo", "mac80211_hwsim"])
    iw_code, iw_out, iw_err = _run(["iw", "dev"])
    link_code, link_out, link_err = _run(["ip", "-br", "link"])
    interfaces = _parse_iw_interfaces(iw_out) if iw_code == 0 else []
    try:
        import scapy
        scapy_status = {"available": True, "version": getattr(scapy, "__version__", "unknown")}
    except Exception as exc:
        scapy_status = {"available": False, "error": str(exc)}
    _, lsmod, _ = _run(["lsmod"])
    module_loaded = "mac80211_hwsim" in lsmod
    blocker = None
    if iw_code != 0:
        blocker = iw_err or "iw could not enumerate wireless devices"
    elif not mod_out:
        blocker = mod_err or "mac80211_hwsim module metadata is unavailable"

    # Inspect Kali Linux wireless auditing toolsuite
    tools = {
        "aircrack_ng": shutil.which("aircrack-ng") is not None,
        "airmon_ng": shutil.which("airmon-ng") is not None,
        "airodump_ng": shutil.which("airodump-ng") is not None,
        "wireshark": shutil.which("wireshark") is not None,
        "tshark": shutil.which("tshark") is not None,
    }

    return {
        "kernel": f"{kernel.sysname} {kernel.release} {kernel.machine}",
        "mac80211_hwsim": {"available": bool(mod_out), "loaded": module_loaded, "module_info": mod_out, "error": mod_err or None},
        "iw": {"available": shutil.which("iw") is not None, "error": iw_err or None},
        "ip": {"available": shutil.which("ip") is not None, "error": link_err or None},
        "scapy": scapy_status,
        "interfaces": interfaces,
        "link_output": link_out,
        "capture_ready": bool(interfaces and scapy_status["available"]),
        "blocker": blocker,
        "tools": tools,
    }


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class LiveLab:
    """Process-wide live capture and monitoring session."""

    def __init__(self, persist: Callable[[Any], dict[str, Any]] | None = None) -> None:
        self._lock = threading.RLock()
        self._subscribers: list[queue.Queue[dict[str, Any]]] = []
        self._capture_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._persist = persist
        self.engine = RuleEngine()
        self.run_id = ""
        self.scenario = "normal"
        self.status = "stopped"
        self.capture_interface: str | None = None
        self.started_at: str | None = None
        self.stopped_at: str | None = None
        self.error: str | None = None
        self.events: list[dict[str, Any]] = []
        self.networks: dict[str, NetworkFeatures] = {}
        self.findings: dict[str, dict[str, Any]] = {}
        self._beacons: dict[str, list[Any]] = {}
        self._deauth: dict[str, list[Any]] = {}
        self._eapol: dict[str, list[Any]] = {}
        self._clients: set[str] = set()
        self.risk_history: list[dict[str, Any]] = []
        self.timeline = "NORMAL"
        self.alert: dict[str, Any] | None = None
        self.persisted_assessment_id: str | None = None
        self.packet_count = 0
        self.packets_per_second = 0.0
        self._last_rate_time = 0.0
        self._last_rate_count = 0

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            network_items = []
            for net in self.networks.values():
                findings = [f for f in self.findings.values() if f.get("bssid") == net.bssid]
                na = NetworkAssessment(net, [])
                network_items.append({
                    **_na_to_dict(na),
                    "clients": len(self._clients),
                    "findings": findings,
                    "risk_score": sum(RISK_SCORES.get(f["severity"], 0) for f in findings),
                    "highest_severity": findings[0]["severity"] if findings else None,
                })

            from wsa.analysis.device_tracker import resolve_vendor, is_locally_administered
            device_items = [
                {
                    "mac": mac,
                    "vendor": resolve_vendor(mac),
                    "is_randomized": is_locally_administered(mac),
                }
                for mac in sorted(list(self._clients))
            ]

            mode_label = "offline_playback" if self.capture_interface == "playback" else "actual_scapy_capture"
            return {
                "run_id": self.run_id,
                "scenario": self.scenario,
                "scenario_label": SCENARIOS.get(self.scenario, self.scenario),
                "status": self.status,
                "capture_interface": self.capture_interface,
                "capture_mode": mode_label,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "error": self.error,
                "packets": self.packet_count,
                "packets_per_second": self.packets_per_second,
                "clients": len(self._clients),
                "devices": device_items,
                "events": list(self.events),
                "networks": network_items,
                "findings": list(self.findings.values()),
                "risk_score": self._risk(),
                "risk_history": list(self.risk_history),
                "timeline": self.timeline,
                "alert": self.alert,
                "assessment_id": self.persisted_assessment_id,
            }

    def subscribe(self) -> queue.Queue[dict[str, Any]]:
        q: queue.Queue[dict[str, Any]] = queue.Queue()
        with self._lock:
            self._subscribers.append(q)
            q.put({"type": "snapshot", "data": self.snapshot()})
        return q

    def unsubscribe(self, q: queue.Queue[dict[str, Any]]) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _publish(self, message: dict[str, Any]) -> None:
        for subscriber in list(self._subscribers):
            subscriber.put(message)

    def start(self, scenario: str, interface: str | None = None, mode: str | None = None) -> dict[str, Any]:
        project_root = Path(__file__).resolve().parents[2]
        is_known = (
            scenario in SCENARIOS
            or (project_root / "data" / "simulated" / scenario).exists()
            or (project_root / "data" / "simulated" / f"{scenario}.pcapng").exists()
            or (project_root / "data" / "samples" / scenario).exists()
            or (project_root / "data" / "samples" / f"{scenario}.pcapng").exists()
        )
        scenario = scenario if is_known else "normal"
        capability = diagnostics()
        selected = interface
        is_playback = (mode == "playback") or (selected in ("playback", "simulated", "offline_replay"))

        with self._lock:
            self._stop.set()
            if self._capture_thread and self._capture_thread.is_alive() and self._capture_thread != threading.current_thread():
                self._capture_thread.join(timeout=0.2)
            self._reset_locked(scenario)

            if is_playback:
                self.capture_interface = "playback"
                self.status = "capturing"
                self.started_at = _timestamp()
                self._stop.clear()
                self._emit("capture_started", "playback", f"Adapter-independent simulation playback started ({scenario})")
                self._capture_thread = threading.Thread(target=self._playback_loop, name="wsa-playback", daemon=True)
                self._capture_thread.start()
                return self.snapshot()

            if not selected:
                selected = next((item["name"] for item in capability["interfaces"] if item.get("type") == "monitor"), None) or (
                    capability["interfaces"][0]["name"] if capability["interfaces"] else None
                )

            self.capture_interface = selected
            if not selected:
                self.status = "error"
                self.error = capability.get("blocker") or "No wireless capture interface is available."
                self._emit("capture_error", "capture", self.error)
                return self.snapshot()

            self.status = "capturing"
            self.started_at = _timestamp()
            self._stop.clear()
            self._emit("capture_started", selected, "incremental Scapy capture started")
            self._capture_thread = threading.Thread(target=self._capture_loop, name="wsa-live-capture", daemon=True)
            self._capture_thread.start()
            return self.snapshot()

    def pause(self) -> dict[str, Any]:
        with self._lock:
            if self.status == "capturing":
                self.status = "paused"
                self._emit("capture_paused", self.capture_interface or "capture", "capture paused")
            return self.snapshot()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._stop.set()
            if self.status in {"capturing", "paused"}:
                self.status = "stopped"
                self.stopped_at = _timestamp()
                self._emit("capture_stopped", self.capture_interface or "capture", "capture stopped")
            if self.packet_count and self._persist and not self.persisted_assessment_id:
                self.persisted_assessment_id = self._persist(self).get("id")
            return self.snapshot()

    def reset(self) -> dict[str, Any]:
        with self._lock:
            self._stop.set()
            self._reset_locked(self.scenario)
            self._publish({"type": "state", "data": self.snapshot()})
            return self.snapshot()

    def _reset_locked(self, scenario: str) -> None:
        self.run_id = uuid.uuid4().hex[:10]
        self.scenario, self.status = scenario, "stopped"
        self.capture_interface = None
        self.started_at = self.stopped_at = self.error = None
        self.events, self.networks, self.findings, self.risk_history = [], {}, {}, []
        self._beacons, self._deauth, self._eapol, self._clients = {}, {}, {}, set()
        self.timeline = "NORMAL"
        self.alert = None
        self.persisted_assessment_id = None
        self.packet_count = 0
        self.packets_per_second = 0.0
        self._last_rate_time = time.monotonic()
        self._last_rate_count = 0

    def _capture_loop(self) -> None:
        try:
            from scapy.all import sniff
            while not self._stop.is_set():
                if self.status == "paused":
                    time.sleep(0.1)
                    continue
                sniff(iface=self.capture_interface, prn=self._on_packet, store=False, timeout=1)
        except Exception as exc:
            with self._lock:
                self.status = "error"
                self.error = f"Live capture failed on {self.capture_interface}: {exc}"
                self._emit("capture_error", self.capture_interface or "capture", self.error)

    def _playback_loop(self) -> None:
        """Adapter-independent offline simulation playback."""
        try:
            from wsa.ingestion.pcap_reader import load_pcap
            project_root = Path(__file__).resolve().parents[2]
            target_name = SCENARIO_PCAPS.get(self.scenario, self.scenario)
            if not target_name.endswith((".pcap", ".pcapng")):
                target_name = f"{target_name}.pcapng"

            pcap_file = project_root / "data" / "simulated" / target_name
            if not pcap_file.exists():
                pcap_file = project_root / "data" / "samples" / target_name
            if not pcap_file.exists():
                pcap_file = project_root / "data" / "simulated" / "mixed_environment.pcapng"
            pkts, _ = load_pcap(str(pcap_file))
            idx = 0
            while not self._stop.is_set() and idx < len(pkts):
                if self.status == "paused":
                    time.sleep(0.1)
                    continue
                pkt = pkts[idx]
                idx += 1
                self._on_packet(pkt)
                time.sleep(0.15)
            if not self._stop.is_set():
                with self._lock:
                    self.status = "stopped"
                    self.stopped_at = _timestamp()
                    self._emit("capture_stopped", "playback", "simulation playback finished")
                    if self.packet_count and self._persist and not self.persisted_assessment_id:
                        self.persisted_assessment_id = self._persist(self).get("id")
                    self._publish({"type": "state", "data": self.snapshot()})
        except Exception as exc:
            with self._lock:
                self.status = "error"
                self.error = f"Simulation playback error: {exc}"
                self._emit("capture_error", "playback", self.error)

    def _on_packet(self, packet: Any) -> None:
        with self._lock:
            if self.status != "capturing":
                return
            self.packet_count += 1
            now = time.monotonic()
            elapsed = now - self._last_rate_time
            if elapsed >= 1:
                self.packets_per_second = (self.packet_count - self._last_rate_count) / elapsed
                self._last_rate_count, self._last_rate_time = self.packet_count, now
            try:
                from wsa.ingestion.frame_parser import parse_frames
                self._process_parsed(parse_frames([packet]))
            except Exception as exc:
                self._emit("frame_error", "frame", f"malformed frame ignored: {exc}")
            self._emit("frame_observed", "frame", f"802.11 frame {self.packet_count} observed")
            self._publish({"type": "state", "data": self.snapshot()})

    def _process_parsed(self, parsed: Any) -> None:
        from wsa.analysis.beacon_extractor import extract_networks
        from wsa.analysis.probe_extractor import extract_client_macs
        for beacon in parsed.beacon_frames:
            extracted = extract_networks([beacon], [], [])
            if not extracted:
                continue
            observed = extracted[0]
            self._beacons.setdefault(observed.bssid, []).append(beacon)
            self.networks[observed.bssid] = extract_networks(
                self._beacons[observed.bssid],
                self._deauth.get(observed.bssid, []),
                self._eapol.get(observed.bssid, []),
            )[0]
            self._emit("network_discovered", observed.bssid, f"SSID {observed.ssid!r} observed")
            self._evaluate(self.networks[observed.bssid])
        for client in extract_client_macs(parsed.probe_requests):
            if client not in self._clients:
                self._clients.add(client)
                self._emit("client_discovered", client, "client observed from probe request")
        for frame in parsed.deauth_frames:
            self._associate_control_frame(frame, self._deauth)
        for frame in parsed.eapol_frames:
            self._associate_control_frame(frame, self._eapol)
        for bssid in set(self._deauth) | set(self._eapol):
            if bssid in self._beacons:
                self.networks[bssid] = extract_networks(
                    self._beacons[bssid],
                    self._deauth.get(bssid, []),
                    self._eapol.get(bssid, []),
                )[0]
                self._evaluate(self.networks[bssid])

    def _associate_control_frame(self, frame: Any, collection: dict[str, list[Any]]) -> None:
        from scapy.layers.dot11 import Dot11
        if not frame.haslayer(Dot11):
            return
        addresses = {getattr(frame[Dot11], field, "") for field in ("addr1", "addr2", "addr3")}
        for bssid in self.networks:
            if bssid in addresses:
                collection.setdefault(bssid, []).append(frame)

    def _evaluate(self, net: NetworkFeatures) -> None:
        for finding in self.engine.evaluate_network(net):
            key = f"{finding.rule_id}:{finding.bssid}"
            item = {
                "rule_id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity,
                "title": finding.title,
                "explanation": finding.explanation,
                "impact": finding.impact,
                "remediation": finding.remediation,
                "evidence": finding.evidence,
                "bssid": finding.bssid,
                "network_ssid": finding.ssid,
            }
            if key not in self.findings:
                self.findings[key] = item
                self._emit("finding_created", finding.rule_id, f"{finding.title} triggered on {finding.ssid or finding.bssid}")
                if finding.severity in {"CRITICAL", "HIGH"}:
                    self.alert = {
                        "title": finding.title,
                        "rule_id": finding.rule_id,
                        "severity": finding.severity,
                        "network": finding.ssid or finding.bssid,
                        "observed_events": net.deauth_count or net.beacon_count,
                        "risk_score": self._risk(),
                        "remediation": finding.remediation,
                        "impact": finding.impact,
                    }
                    self.timeline = "ALERT"
                    self._emit("alert", finding.ssid or finding.bssid, finding.title)
        score = self._risk()
        if not self.risk_history or self.risk_history[-1]["score"] != score:
            self.risk_history.append({
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "score": score,
                "event": self.events[-1]["type"] if self.events else "",
            })
            self._emit("risk_updated", net.ssid or net.bssid, f"risk score updated to {score}")

    def _risk(self) -> int:
        return sum(RISK_SCORES.get(item["severity"], 0) for item in self.findings.values())

    def _emit(self, event_type: str, target: str, message: str) -> None:
        event = {
            "id": len(self.events) + 1,
            "type": event_type,
            "timestamp": _timestamp(),
            "target": target,
            "message": message,
        }
        self.events.append(event)
        self._publish({"type": "event", "data": event, "event_type": event_type})

    def assessment(self) -> Assessment:
        with self._lock:
            pairs = [(net, self.engine.evaluate_network(net)) for net in self.networks.values()]
            scan = ScanFeatures(
                source_file=f"live-{self.run_id}.json",
                data_source="virtual_lab",
                total_frames=self.packet_count,
                networks=list(self.networks.values()),
                total_deauth_frames=sum(n.deauth_count for n in self.networks.values()),
            )
            return build_assessment(scan, pairs)
