"""Dependency free HTTP server exposing the assessment application API."""
from __future__ import annotations

import json
import mimetypes
import os
import queue
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from wsa.api.serializers import assessment_summary, public_assessment
from wsa.api.storage import AssessmentStore
from wsa.api.live_lab import LiveLab, SCENARIOS, diagnostics
from wsa.comparison import compare_assessments

MAX_UPLOAD_BYTES = 50 * 1024 * 1024


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class WSAHandler(BaseHTTPRequestHandler):
    store = AssessmentStore()
    live = LiveLab()
    server_version = "WSA/1.0"

    def log_message(self, format: str, *args: object) -> None:
        print(f"[wsa-api] {self.address_string()} - {format % args}")

    def _send(self, status: int, body: object, content_type: str = "application/json; charset=utf-8") -> None:
        payload = body if isinstance(body, bytes) else _json_bytes(body)
        origin = self.headers.get("Origin") or os.environ.get("WSA_CORS_ORIGIN", "*")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin") or os.environ.get("WSA_CORS_ORIGIN", "*")
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        origin = self.headers.get("Origin") or os.environ.get("WSA_CORS_ORIGIN", "*")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        route = [part for part in parsed.path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if route == ["api", "health"]:
                return self._send(200, {"status": "ok", "engine": "operational"})
            if route == ["api", "dashboard"]:
                return self._dashboard()
            if route == ["api", "assessments"]:
                return self._assessments()
            if len(route) == 3 and route[:2] == ["api", "assessments"]:
                return self._assessment(route[2])
            if len(route) == 4 and route[:2] == ["api", "assessments"] and route[3] == "devices":
                return self._assessment_devices(route[2])
            if len(route) == 4 and route[:2] == ["api", "assessments"] and route[3] == "protocol":
                return self._assessment_protocol(route[2])
            if route == ["api", "networks"]:
                return self._networks()
            if route == ["api", "devices"]:
                return self._devices()
            if route == ["api", "compare"]:
                return self._compare(query)
            if route == ["api", "findings"]:
                return self._findings(query)
            if route == ["api", "reports"]:
                return self._reports()
            if route == ["api", "live", "state"]:
                return self._send(200, self.live.snapshot())
            if route == ["api", "live", "diagnostics"]:
                return self._send(200, diagnostics())
            if route == ["api", "live", "interfaces"]:
                return self._send(200, {"items": diagnostics()["interfaces"]})
            if route == ["api", "live", "stream"]:
                return self._live_stream()
            if len(route) == 5 and route[:2] == ["api", "reports"] and route[4] == "download":
                return self._download(route[2], route[3])
            return self._send(404, {"error": "Endpoint not found"})
        except Exception as exc:
            return self._send(500, {"error": f"Unexpected server error: {exc}"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/compare":
            return self._compare_post()
        if parsed.path.startswith("/api/live/"):
            return self._live_command(parsed.path.rsplit("/", 1)[-1])
        if parsed.path == "/api/assessments/sample":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "Invalid JSON body"})
            sample_name = data.get("sample", "mixed_environment.pcapng")
            from pathlib import Path
            project_root = Path(__file__).resolve().parents[2]
            sample_path = project_root / "data" / "simulated" / Path(sample_name).name
            if not sample_path.exists():
                sample_path = project_root / "data" / "samples" / Path(sample_name).name
            if not sample_path.exists():
                return self._send(404, {"error": f"Sample capture '{sample_name}' not found"})
            payload = sample_path.read_bytes()
            record = self.store.create(sample_path.name, payload, data.get("data_source", "simulated"))
            return self._send(201, public_assessment(record["id"], record))
        if parsed.path != "/api/assessments":
            return self._send(404, {"error": "Endpoint not found"})
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_UPLOAD_BYTES + 1024 * 1024:
            return self._send(413, {"error": "Upload exceeds the 50 MB size limit"})
        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("multipart/form-data"):
            return self._send(400, {"error": "Use multipart/form-data with a file and data_source"})
        body = self.rfile.read(length)
        try:
            message = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
            )
            data_source = ""
            filename = None
            payload = b""
            for part in message.iter_parts():
                disposition = part.get_content_disposition()
                field_name = part.get_param("name", header="content-disposition")
                if disposition != "form-data":
                    continue
                if field_name == "data_source":
                    data_source = part.get_content().strip()
                elif field_name == "file":
                    filename = part.get_filename()
                    payload = part.get_payload(decode=True) or b""
            if len(payload) > MAX_UPLOAD_BYTES:
                return self._send(413, {"error": "Upload exceeds the 50 MB size limit"})
            if not filename:
                return self._send(400, {"error": "A PCAP or PCAPNG file is required"})
            record = self.store.create(filename, payload, data_source)
            return self._send(201, public_assessment(record["id"], record))
        except ValueError as exc:
            return self._send(400, {"error": str(exc)})
        except Exception as exc:
            if exc.__class__.__name__ == "PcapReadError":
                return self._send(400, {"error": str(exc)})
            return self._send(422, {"error": f"Assessment could not be completed: {exc}"})

    def _compare_post(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "Invalid JSON body"})
        baseline_id = data.get("baseline")
        target_id = data.get("target")
        if not baseline_id or not target_id:
            return self._send(400, {"error": "Fields 'baseline' and 'target' are required"})
        baseline = self.store.get_record(baseline_id)
        target = self.store.get_record(target_id)
        if not baseline:
            return self._send(404, {"error": f"Baseline assessment '{baseline_id}' not found"})
        if not target:
            return self._send(404, {"error": f"Target assessment '{target_id}' not found"})
        result = compare_assessments(baseline, target)
        return self._send(200, result)

    def _compare(self, query: dict[str, list[str]]) -> None:
        baseline_id = query.get("baseline", [""])[0]
        target_id = query.get("target", [""])[0]
        if not baseline_id or not target_id:
            return self._send(400, {"error": "Query parameters 'baseline' and 'target' are required"})
        baseline = self.store.get_record(baseline_id)
        target = self.store.get_record(target_id)
        if not baseline:
            return self._send(404, {"error": f"Baseline assessment '{baseline_id}' not found"})
        if not target:
            return self._send(404, {"error": f"Target assessment '{target_id}' not found"})
        result = compare_assessments(baseline, target)
        return self._send(200, result)

    def _assessment_devices(self, assessment_id: str) -> None:
        record = self.store.get_record(assessment_id)
        if not record:
            return self._send(404, {"error": "Assessment not found"})
        return self._send(200, {"items": record.get("devices", [])})

    def _assessment_protocol(self, assessment_id: str) -> None:
        record = self.store.get_record(assessment_id)
        if not record:
            return self._send(404, {"error": "Assessment not found"})
        return self._send(200, record.get("protocol_analysis", {}))

    def _devices(self) -> None:
        items = []
        for record in self.store.list_records():
            for dev in record.get("devices", []):
                items.append({
                    "assessment_id": record["id"],
                    "assessment_filename": record.get("filename"),
                    **dev,
                })
        return self._send(200, {"items": items})

    def _live_command(self, command: str) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "Invalid JSON command"})
        if command == "start":
            scenario = data.get("scenario", "normal")
            if scenario not in SCENARIOS:
                from pathlib import Path
                project_root = Path(__file__).resolve().parents[2]
                is_file = (
                    (project_root / "data" / "simulated" / scenario).exists()
                    or (project_root / "data" / "simulated" / f"{scenario}.pcapng").exists()
                    or (project_root / "data" / "samples" / scenario).exists()
                    or (project_root / "data" / "samples" / f"{scenario}.pcapng").exists()
                )
                if not is_file:
                    scenario = "normal"
            self.live._persist = self.store.create_live
            return self._send(200, self.live.start(scenario, data.get("interface"), data.get("mode")))
        if command == "pause":
            return self._send(200, self.live.pause())
        if command == "stop":
            return self._send(200, self.live.stop())
        if command == "reset":
            return self._send(200, self.live.reset())
        return self._send(404, {"error": "Unknown live command"})

    def _live_stream(self) -> None:
        subscriber = self.live.subscribe()
        origin = self.headers.get("Origin") or os.environ.get("WSA_CORS_ORIGIN", "*")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", origin)
            self.end_headers()
            while True:
                try:
                    message = subscriber.get(timeout=15)
                    payload = json.dumps(message, ensure_ascii=False)
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.live.unsubscribe(subscriber)

    def _dashboard(self) -> None:
        records = self.store.list_records()
        summaries = [assessment_summary(r["id"], r) for r in records]
        severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        networks = []
        devices = []
        for record in records:
            severity_counts = record.get("summary", {}).get("severity_counts", {})
            for key in severity:
                severity[key] += int(severity_counts.get(key, 0))
            networks.extend(record.get("networks", []))
            devices.extend(record.get("devices", []))
        risk_total = sum(int(item.get("total_risk_score", 0)) for item in summaries)
        return self._send(200, {
            "total_assessments": len(records),
            "total_networks": len(networks),
            "total_devices": len(devices),
            "total_findings": sum(severity.values()),
            "overall_risk": risk_total,
            "severity_counts": severity,
            "recent_assessments": summaries[:5],
            "recent_findings": self._finding_items(records)[:6],
        })

    def _assessments(self) -> None:
        return self._send(200, {"items": self.store.summaries()})

    def _assessment(self, assessment_id: str) -> None:
        record = self.store.get_record(assessment_id)
        if not record:
            return self._send(404, {"error": "Assessment not found"})
        return self._send(200, public_assessment(assessment_id, record))

    def _networks(self) -> None:
        items = []
        for record in self.store.list_records():
            for network in record.get("networks", []):
                items.append({"assessment_id": record["id"], "assessment_filename": record.get("filename"), **network})
        return self._send(200, {"items": items})

    def _finding_items(self, records: list[dict]) -> list[dict]:
        items = []
        for record in records:
            for network in record.get("networks", []):
                for finding in network.get("findings", []):
                    items.append({
                        "assessment_id": record["id"],
                        "assessment_filename": record.get("filename"),
                        "network_ssid": network.get("ssid"),
                        "network_bssid": network.get("bssid"),
                        **finding,
                    })
        return items

    def _findings(self, query: dict[str, list[str]]) -> None:
        items = self._finding_items(self.store.list_records())
        severity = query.get("severity", [""])[0].upper()
        search = query.get("search", [""])[0].lower().strip()
        if severity and severity != "ALL":
            items = [item for item in items if item.get("severity") == severity]
        if search:
            items = [item for item in items if search in json.dumps(item).lower()]
        return self._send(200, {"items": items})

    def _reports(self) -> None:
        reports = []
        for record in self.store.list_records():
            for report_format in ("pdf", "html", "json", "md"):
                path = self.store.report_path(record["id"], report_format)
                if path:
                    reports.append({
                        "assessment_id": record["id"],
                        "filename": record.get("filename"),
                        "format": report_format,
                        "download_url": f"/api/reports/{record['id']}/{report_format}/download"
                    })
        return self._send(200, {"items": reports})

    def _download(self, assessment_id: str, report_format: str) -> None:
        path = self.store.report_path(assessment_id, report_format)
        if not path or not path.exists():
            return self._send(404, {"error": "Report not found"})
        content_type = mimetypes.guess_type(path.name)[0] or (
            "application/pdf" if report_format == "pdf" else "application/octet-stream"
        )
        payload = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.send_header("Content-Length", str(len(payload)))
        origin = self.headers.get("Origin") or os.environ.get("WSA_CORS_ORIGIN", "*")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(payload)


def run(host: str | None = None, port: int = 8000) -> None:
    host_addr = host or os.environ.get("WSA_HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host_addr, port), WSAHandler)
    print(f"WSA API listening at http://{host_addr}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
