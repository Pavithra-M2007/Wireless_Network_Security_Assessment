"""Small file based store for assessment results and generated reports."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

from wsa.api.serializers import assessment_summary
from wsa.reporting.assessment import assess_pcap
from wsa.reporting.html_reporter import to_html
from wsa.reporting.json_reporter import to_json
from wsa.reporting.markdown_reporter import to_markdown
from wsa.reporting.pdf_reporter import to_pdf

_SAFE_ID = re.compile(r"^[a-f0-9]{12}$")
_ALLOWED_SUFFIXES = {".pcap", ".pcapng"}


class AssessmentStore:
    """Persist uploaded captures, report artifacts, and assessment metadata."""

    def __init__(self, root: Path | None = None) -> None:
        project_root = Path(__file__).resolve().parents[2]
        self.root = (root or project_root / "data" / "app").resolve()
        self.uploads = self.root / "uploads"
        self.records = self.root / "assessments"
        self.reports = self.root / "reports"
        for directory in (self.uploads, self.records, self.reports):
            directory.mkdir(parents=True, exist_ok=True)

    def list_records(self) -> list[dict[str, Any]]:
        records = []
        for path in self.records.glob("*.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                records.append(record)
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(records, key=lambda r: r.get("analysis_timestamp", ""), reverse=True)

    def get_record(self, assessment_id: str) -> dict[str, Any] | None:
        if not _SAFE_ID.fullmatch(assessment_id):
            return None
        path = self.records / f"{assessment_id}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def create(self, filename: str, payload: bytes, data_source: str) -> dict[str, Any]:
        suffix = Path(filename).suffix.lower()
        if suffix not in _ALLOWED_SUFFIXES:
            raise ValueError("Only .pcap and .pcapng files are supported")
        if data_source not in {"simulated", "real", "pcap_offline"}:
            raise ValueError("data_source must be 'pcap_offline', 'simulated', or 'real'")
        if not payload:
            raise ValueError("The uploaded capture is empty")

        assessment_id = uuid.uuid4().hex[:12]
        safe_name = Path(filename).name
        upload_path = self.uploads / f"{assessment_id}{suffix}"
        upload_path.write_bytes(payload)
        try:
            assessment = assess_pcap(str(upload_path), data_source=data_source)
        except Exception:
            upload_path.unlink(missing_ok=True)
            raise

        report_dir = self.reports / assessment_id
        report_dir.mkdir(parents=True, exist_ok=True)
        json_report = json.loads(to_json(assessment))
        json_report.pop("source_file", None)
        json_report["source_filename"] = safe_name

        # Extract client stations and deep protocol stats
        try:
            from wsa.ingestion.pcap_reader import load_pcap
            from wsa.analysis.device_tracker import extract_stations
            from wsa.analysis.protocol_analyzer import analyze_protocol_and_packets
            pkts, _ = load_pcap(str(upload_path))
            stations = extract_stations(pkts, assessment.network_assessments)
            json_report["devices"] = [s.to_dict() for s in stations]
            json_report["protocol_analysis"] = analyze_protocol_and_packets(pkts)
        except Exception:
            json_report["devices"] = []
            json_report["protocol_analysis"] = {}

        (report_dir / f"{safe_name}.json").write_text(
            json.dumps(json_report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (report_dir / f"{safe_name}.md").write_text(to_markdown(assessment), encoding="utf-8")
        (report_dir / f"{safe_name}.html").write_text(to_html(assessment), encoding="utf-8")

        data = json_report
        data["source_filename"] = safe_name
        data.pop("source_file", None)
        record = {"id": assessment_id, "filename": safe_name, "report_dir": str(report_dir), **data}
        (self.records / f"{assessment_id}.json").write_text(
            json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return record

    def create_live(self, lab: Any) -> dict[str, Any]:
        """Persist a completed safe-live-lab run through the normal reporters."""
        assessment = lab.assessment()
        assessment_id = uuid.uuid4().hex[:12]
        filename = f"live-lab-{lab.run_id}.json"
        report_dir = self.reports / assessment_id
        report_dir.mkdir(parents=True, exist_ok=True)
        json_report = json.loads(to_json(assessment))
        json_report.pop("source_file", None)
        json_report["source_filename"] = filename

        # Add devices from lab
        devices = []
        for client_mac in getattr(lab, "_clients", set()):
            from wsa.analysis.device_tracker import resolve_vendor, is_locally_administered
            devices.append({
                "mac": client_mac,
                "vendor": resolve_vendor(client_mac),
                "is_randomized": is_locally_administered(client_mac),
                "frame_count": 1,
                "threat_indicators": [],
                "probed_ssids": [],
            })
        json_report["devices"] = devices
        json_report["protocol_analysis"] = {
            "total_packets": lab.packet_count,
            "categories": {"management": lab.packet_count, "control": 0, "data": 0, "unknown": 0},
            "subtypes": {"Beacon": sum(n.beacon_count for n in lab.networks.values()), "Deauth": sum(n.deauth_count for n in lab.networks.values())},
            "channels": {},
            "samples": [],
        }

        (report_dir / f"{filename}.json").write_text(json.dumps(json_report, indent=2, ensure_ascii=False), encoding="utf-8")
        (report_dir / f"{filename}.md").write_text(to_markdown(assessment), encoding="utf-8")
        (report_dir / f"{filename}.html").write_text(to_html(assessment), encoding="utf-8")
        record = {"id": assessment_id, "filename": filename, "report_dir": str(report_dir), **json_report}
        (self.records / f"{assessment_id}.json").write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        return record

    def summaries(self) -> list[dict[str, Any]]:
        return [assessment_summary(record["id"], record) for record in self.list_records()]

    def report_path(self, assessment_id: str, report_format: str) -> Path | None:
        record = self.get_record(assessment_id)
        if not record or report_format not in {"json", "md", "html", "pdf"}:
            return None
        report_dir = Path(record.get("report_dir", ""))
        if report_dir.parent != self.reports or report_dir.name != assessment_id:
            return None
        matches = list(report_dir.glob(f"*.{report_format}"))
        if matches:
            return matches[0]
        if report_format == "pdf":
            safe_name = record.get("filename", f"report-{assessment_id}")
            if safe_name.endswith((".pcap", ".pcapng", ".json", ".html", ".md")):
                safe_name = Path(safe_name).stem
            pdf_path = report_dir / f"{safe_name}.pdf"
            try:
                to_pdf(record, output_path=pdf_path)
                return pdf_path
            except Exception:
                return None
        return None
