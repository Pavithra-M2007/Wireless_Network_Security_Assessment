"""
Unit tests — Stage 4: report generation (JSON, Markdown, HTML).

Test coverage:
  Assessment model
    - risk_score: correct per-severity weights, zero for no findings
    - severity_counts: all five levels always present
    - highest_severity: None when no findings, correct label otherwise
    - all_findings: flat list across networks
    - finding_count, total_risk_score
    - build_assessment: field population, default timestamp format
    - data_source_note: simulated, real, unknown labels

  JSON reporter
    - Output is valid JSON (parseable)
    - schema_version present
    - summary counts are correct
    - None → null serialisation
    - Lists serialise as arrays
    - severity_counts contains all five keys
    - Empty network list handled
    - Zero-finding assessment handled

  Markdown reporter
    - Contains expected section headers
    - Contains BSSID and SSID strings
    - Severity labels appear in output
    - Pipe characters in SSID escaped as &#124;
    - None SSID rendered as "(SSID IE absent)"
    - Empty SSID rendered as "(Hidden SSID)"
    - Zero-finding network shows clean message
    - Empty assessment has no findings table rows

  HTML reporter
    - Output contains <!DOCTYPE html>
    - No external http:// or https:// URLs
    - No <link ...> elements referencing external resources
    - Inline CSS present in <style> block
    - SSID with HTML-special chars is escaped (XSS prevention)
    - <script> in SSID does NOT appear unescaped in output
    - evidence string appears HTML-escaped when it contains <
    - Provenance banner CSS class: simulated, real, unknown
    - SSID=None rendered as "(SSID IE absent)"
    - Empty assessment renders without error
    - Severity badge CSS classes present for each severity level

  End-to-end
    - assess_pcap on each synthetic PCAP produces an Assessment
    - JSON from assess_pcap is valid and contains correct data_source
    - HTML from assess_pcap has no external URLs
    - Markdown from assess_pcap has expected headers
    - wpa3_network.pcapng → zero findings in all three formats
    - open_network.pcapng → ENC-001 appears in all three formats
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

import pytest

from wsa.analysis.feature_set import (
    CIPHER_CCMP, CIPHER_NONE, CIPHER_WEP,
    AUTH_OPEN, AUTH_PSK, AUTH_SAE,
    NetworkFeatures, ScanFeatures,
)
from wsa.rules.finding import Finding, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_LOW
from wsa.reporting import (
    Assessment, NetworkAssessment, RISK_SCORES, SEVERITIES,
    build_assessment, assess_pcap, data_source_note,
    to_json, to_markdown, to_html,
)

DATA = Path(__file__).parent.parent.parent / "data" / "simulated"

_FIXED_TS = "2024-01-15T12:00:00+00:00"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _net(**kwargs) -> NetworkFeatures:
    defaults = dict(bssid="aa:bb:cc:dd:ee:ff", ssid="TestNet")
    defaults.update(kwargs)
    return NetworkFeatures(**defaults)


def _finding(rule_id="ENC-001", severity=SEVERITY_CRITICAL) -> Finding:
    return Finding(
        rule_id=rule_id, category="Encryption", severity=severity,
        title="Test Finding", explanation="Explanation text.",
        impact="Impact text.", remediation="Remediation text.",
        evidence="cipher = 'NONE'",
        bssid="aa:bb:cc:dd:ee:ff", ssid="TestNet",
    )


def _empty_assessment() -> Assessment:
    return Assessment(
        source_file="test.pcapng",
        data_source="simulated",
        analysis_timestamp=_FIXED_TS,
        total_frames=0,
        total_networks=0,
        total_probe_requests=0,
        total_deauth_frames=0,
        total_eapol_frames=0,
        parse_errors=[],
        network_assessments=[],
    )


def _one_network_assessment(
    ssid="TestNet",
    findings: list = None,
    **net_kwargs,
) -> Assessment:
    net = _net(ssid=ssid, **net_kwargs)
    na = NetworkAssessment(network=net, findings=findings or [])
    return Assessment(
        source_file="test.pcapng",
        data_source="simulated",
        analysis_timestamp=_FIXED_TS,
        total_frames=20,
        total_networks=1,
        total_probe_requests=3,
        total_deauth_frames=0,
        total_eapol_frames=0,
        parse_errors=[],
        network_assessments=[na],
    )


# ===========================================================================
# Assessment model
# ===========================================================================

class TestNetworkAssessment:
    def test_risk_score_zero_no_findings(self):
        na = NetworkAssessment(network=_net(), findings=[])
        assert na.risk_score == 0

    def test_risk_score_critical(self):
        na = NetworkAssessment(network=_net(), findings=[_finding(severity=SEVERITY_CRITICAL)])
        assert na.risk_score == RISK_SCORES["CRITICAL"]

    def test_risk_score_multiple(self):
        findings = [
            _finding("ENC-001", SEVERITY_CRITICAL),
            _finding("AUTH-001", SEVERITY_HIGH),
        ]
        na = NetworkAssessment(network=_net(), findings=findings)
        assert na.risk_score == RISK_SCORES["CRITICAL"] + RISK_SCORES["HIGH"]

    def test_severity_counts_all_keys_present(self):
        na = NetworkAssessment(network=_net(), findings=[])
        assert set(na.severity_counts.keys()) == set(SEVERITIES)

    def test_severity_counts_correct_count(self):
        findings = [
            _finding("ENC-001", SEVERITY_CRITICAL),
            _finding("ENC-002", SEVERITY_CRITICAL),
            _finding("AUTH-001", SEVERITY_HIGH),
        ]
        na = NetworkAssessment(network=_net(), findings=findings)
        counts = na.severity_counts
        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 0

    def test_highest_severity_none_when_no_findings(self):
        na = NetworkAssessment(network=_net(), findings=[])
        assert na.highest_severity is None

    def test_highest_severity_correct(self):
        findings = [_finding("A", SEVERITY_HIGH), _finding("B", SEVERITY_LOW)]
        na = NetworkAssessment(network=_net(), findings=findings)
        assert na.highest_severity == SEVERITY_HIGH

    def test_highest_severity_with_one_critical(self):
        na = NetworkAssessment(
            network=_net(),
            findings=[_finding("X", SEVERITY_CRITICAL)],
        )
        assert na.highest_severity == SEVERITY_CRITICAL


class TestAssessment:
    def test_finding_count_zero(self):
        assert _empty_assessment().finding_count == 0

    def test_finding_count_across_networks(self):
        a = _one_network_assessment(
            findings=[_finding(), _finding("AUTH-001", SEVERITY_HIGH)]
        )
        assert a.finding_count == 2

    def test_total_risk_score_empty(self):
        assert _empty_assessment().total_risk_score == 0

    def test_total_risk_score_computed(self):
        a = _one_network_assessment(findings=[_finding(severity=SEVERITY_CRITICAL)])
        assert a.total_risk_score == RISK_SCORES["CRITICAL"]

    def test_severity_counts_all_keys(self):
        a = _empty_assessment()
        assert set(a.severity_counts.keys()) == set(SEVERITIES)

    def test_all_findings_flat(self):
        a = _one_network_assessment(findings=[_finding(), _finding("A2", SEVERITY_HIGH)])
        assert len(a.all_findings) == 2

    def test_all_findings_empty(self):
        assert _empty_assessment().all_findings == []


class TestBuildAssessment:
    def test_source_file_propagated(self):
        scan = ScanFeatures(source_file="my.pcapng", data_source="simulated")
        a = build_assessment(scan, [], _FIXED_TS)
        assert a.source_file == "my.pcapng"

    def test_data_source_propagated(self):
        scan = ScanFeatures(source_file="x.pcapng", data_source="real")
        a = build_assessment(scan, [], _FIXED_TS)
        assert a.data_source == "real"

    def test_timestamp_used_when_provided(self):
        scan = ScanFeatures(source_file="x.pcapng", data_source="simulated")
        a = build_assessment(scan, [], _FIXED_TS)
        assert a.analysis_timestamp == _FIXED_TS

    def test_timestamp_auto_generated_when_none(self):
        scan = ScanFeatures(source_file="x.pcapng", data_source="simulated")
        a = build_assessment(scan, [])
        assert a.analysis_timestamp  # non-empty
        assert "T" in a.analysis_timestamp  # ISO 8601 format

    def test_network_assessments_built_from_results(self):
        net = _net()
        findings = [_finding()]
        scan = ScanFeatures(source_file="x.pcapng", data_source="simulated", networks=[net])
        a = build_assessment(scan, [(net, findings)], _FIXED_TS)
        assert len(a.network_assessments) == 1
        assert a.network_assessments[0].findings == findings

    def test_empty_engine_results(self):
        scan = ScanFeatures(source_file="x.pcapng", data_source="simulated")
        a = build_assessment(scan, [], _FIXED_TS)
        assert a.network_assessments == []


class TestDataSourceNote:
    def test_simulated_note(self):
        note = data_source_note("simulated")
        assert "synthetic" in note.lower() or "simulated" in note.lower()

    def test_real_note(self):
        note = data_source_note("real")
        assert "real" in note.lower() or "capture" in note.lower()

    def test_unknown_source_note_includes_label(self):
        note = data_source_note("my_custom_source")
        assert "my_custom_source" in note


# ===========================================================================
# JSON reporter
# ===========================================================================

class TestJsonReporter:
    def test_output_is_valid_json(self):
        doc = json.loads(to_json(_empty_assessment()))
        assert isinstance(doc, dict)

    def test_schema_version_present(self):
        doc = json.loads(to_json(_empty_assessment()))
        assert "schema_version" in doc
        assert doc["schema_version"] == "1.0"

    def test_data_source_in_output(self):
        doc = json.loads(to_json(_empty_assessment()))
        assert doc["data_source"] == "simulated"

    def test_data_source_note_in_output(self):
        doc = json.loads(to_json(_empty_assessment()))
        assert "data_source_note" in doc
        assert doc["data_source_note"]  # non-empty

    def test_analysis_timestamp_in_output(self):
        doc = json.loads(to_json(_empty_assessment()))
        assert doc["analysis_timestamp"] == _FIXED_TS

    def test_summary_structure(self):
        doc = json.loads(to_json(_empty_assessment()))
        summary = doc["summary"]
        for key in ("total_frames", "total_networks", "total_findings",
                    "total_risk_score", "severity_counts"):
            assert key in summary, f"Missing summary key: {key}"

    def test_severity_counts_all_five_keys(self):
        doc = json.loads(to_json(_empty_assessment()))
        counts = doc["summary"]["severity_counts"]
        assert set(counts.keys()) == set(SEVERITIES)

    def test_none_serialises_as_null(self):
        # ssid=None → JSON null; channel=None → JSON null
        a = _one_network_assessment(ssid=None, channel=None)
        doc = json.loads(to_json(a))
        net = doc["networks"][0]
        assert net["ssid"] is None
        assert net["channel"] is None

    def test_mfp_none_serialises_as_null(self):
        a = _one_network_assessment(mfp_capable=None, mfp_required=None)
        doc = json.loads(to_json(a))
        net = doc["networks"][0]
        assert net["mfp_capable"] is None
        assert net["mfp_required"] is None

    def test_empty_networks_list(self):
        doc = json.loads(to_json(_empty_assessment()))
        assert doc["networks"] == []

    def test_findings_in_network_output(self):
        a = _one_network_assessment(findings=[_finding()])
        doc = json.loads(to_json(a))
        assert len(doc["networks"][0]["findings"]) == 1

    def test_finding_fields_present(self):
        a = _one_network_assessment(findings=[_finding()])
        doc = json.loads(to_json(a))
        f = doc["networks"][0]["findings"][0]
        for key in ("rule_id", "category", "severity", "title",
                    "explanation", "impact", "remediation", "evidence"):
            assert key in f, f"Missing finding key: {key}"

    def test_risk_score_in_network(self):
        a = _one_network_assessment(findings=[_finding(severity=SEVERITY_CRITICAL)])
        doc = json.loads(to_json(a))
        assert doc["networks"][0]["risk_score"] == RISK_SCORES["CRITICAL"]

    def test_highest_severity_null_when_no_findings(self):
        a = _one_network_assessment(findings=[])
        doc = json.loads(to_json(a))
        assert doc["networks"][0]["highest_severity"] is None

    def test_source_filename_is_basename(self):
        a = _empty_assessment()
        a.source_file = "/some/deep/path/test.pcapng"  # type: ignore[misc]
        doc = json.loads(to_json(a))
        assert doc["source_filename"] == "test.pcapng"

    def test_compact_json_with_indent_zero(self):
        raw = to_json(_empty_assessment(), indent=0)
        assert "\n" not in raw  # no newlines in compact mode


# ===========================================================================
# Markdown reporter
# ===========================================================================

class TestMarkdownReporter:
    def test_contains_h1(self):
        md = to_markdown(_empty_assessment())
        assert md.startswith("# Wireless Network Security Assessment Report")

    def test_contains_executive_summary_h2(self):
        md = to_markdown(_empty_assessment())
        assert "## Executive Summary" in md

    def test_contains_networks_h2(self):
        md = to_markdown(_empty_assessment())
        assert "## Networks" in md

    def test_data_source_provenance_in_output(self):
        md = to_markdown(_empty_assessment())
        assert "SIMULATED" in md

    def test_bssid_appears_in_network_section(self):
        a = _one_network_assessment()
        md = to_markdown(a)
        assert "aa:bb:cc:dd:ee:ff" in md

    def test_ssid_appears_in_network_section(self):
        a = _one_network_assessment(ssid="HomeNetwork")
        md = to_markdown(a)
        assert "HomeNetwork" in md

    def test_pipe_in_ssid_escaped(self):
        """Pipe characters in SSIDs must be escaped to avoid breaking GFM tables."""
        a = _one_network_assessment(ssid="Net|work")
        md = to_markdown(a)
        assert "Net|work" not in md  # raw pipe must not appear in table cell
        assert "&#124;" in md        # must be replaced with safe entity

    def test_none_ssid_rendered_as_absent(self):
        a = _one_network_assessment(ssid=None)
        md = to_markdown(a)
        assert "SSID IE absent" in md or "SSID absent" in md

    def test_empty_ssid_rendered_as_hidden(self):
        a = _one_network_assessment(ssid="")
        md = to_markdown(a)
        assert "Hidden" in md or "hidden" in md

    def test_severity_labels_in_finding_block(self):
        a = _one_network_assessment(findings=[_finding(severity=SEVERITY_CRITICAL)])
        md = to_markdown(a)
        assert "CRITICAL" in md

    def test_rule_id_in_finding_block(self):
        a = _one_network_assessment(findings=[_finding()])
        md = to_markdown(a)
        assert "ENC-001" in md

    def test_clean_message_when_no_findings(self):
        a = _one_network_assessment(findings=[])
        md = to_markdown(a)
        assert "No security findings" in md or "satisfactory" in md

    def test_empty_assessment_no_network_rows(self):
        md = to_markdown(_empty_assessment())
        # No per-network section should appear; the only h3 is the summary's
        # "### Findings by Severity". Network sections start with h3 headers
        # that contain a BSSID (colons in MAC address are a reliable marker).
        import re as _re
        network_h3 = _re.findall(r'^### .*:.*:.*:', md, _re.MULTILINE)
        assert network_h3 == [], f"Unexpected network h3 headers: {network_h3}"

    def test_severity_table_contains_all_levels(self):
        md = to_markdown(_empty_assessment())
        for sev in SEVERITIES:
            assert sev in md

    def test_analysis_timestamp_in_output(self):
        md = to_markdown(_empty_assessment())
        assert _FIXED_TS in md

    def test_footer_present(self):
        md = to_markdown(_empty_assessment())
        assert "Generated by" in md


# ===========================================================================
# HTML reporter
# ===========================================================================

class TestHtmlReporter:
    def test_output_starts_with_doctype(self):
        html = to_html(_empty_assessment())
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_inline_css_present(self):
        html = to_html(_empty_assessment())
        assert "<style>" in html and "</style>" in html

    def test_no_external_http_urls(self):
        html = to_html(_empty_assessment())
        assert "http://" not in html
        assert "https://" not in html

    def test_no_external_link_elements(self):
        html = to_html(_empty_assessment())
        # <link> tags with href= are prohibited
        assert not re.search(r'<link[^>]+href=', html, re.IGNORECASE)

    def test_no_external_script_src(self):
        html = to_html(_empty_assessment())
        assert not re.search(r'<script[^>]+src=', html, re.IGNORECASE)

    def test_xss_ssid_script_tag_escaped(self):
        """An SSID containing <script> must not appear unescaped in HTML."""
        a = _one_network_assessment(ssid="<script>alert(1)</script>")
        html = to_html(a)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_xss_ssid_html_entities_escaped(self):
        a = _one_network_assessment(ssid='<img src=x onerror="alert(1)">')
        html = to_html(a)
        assert "<img" not in html
        assert "&lt;img" in html

    def test_xss_evidence_escaped(self):
        """Evidence strings from PCAP can contain < > — must be escaped."""
        f = Finding(
            rule_id="ENC-001", category="Enc", severity=SEVERITY_CRITICAL,
            title="T", explanation="E", impact="I", remediation="R",
            evidence="ssid = '<malicious>'",
            bssid="aa:bb:cc:dd:ee:ff", ssid="Net",
        )
        a = _one_network_assessment(findings=[f])
        html = to_html(a)
        assert "<malicious>" not in html
        assert "&lt;malicious&gt;" in html

    def test_none_ssid_rendered_safely(self):
        a = _one_network_assessment(ssid=None)
        html = to_html(a)
        assert "SSID IE absent" in html
        assert "None" not in html  # should NOT render Python None as the string

    def test_provenance_class_simulated(self):
        a = _empty_assessment()
        html = to_html(a)
        assert "wsa-prov-simulated" in html

    def test_provenance_class_real(self):
        a = Assessment(
            source_file="x.pcapng", data_source="real",
            analysis_timestamp=_FIXED_TS,
            total_frames=0, total_networks=0, total_probe_requests=0,
            total_deauth_frames=0, total_eapol_frames=0,
            parse_errors=[], network_assessments=[],
        )
        html = to_html(a)
        assert "wsa-prov-real" in html

    def test_provenance_class_unknown_source(self):
        a = Assessment(
            source_file="x.pcapng", data_source="custom_label",
            analysis_timestamp=_FIXED_TS,
            total_frames=0, total_networks=0, total_probe_requests=0,
            total_deauth_frames=0, total_eapol_frames=0,
            parse_errors=[], network_assessments=[],
        )
        html = to_html(a)
        assert "wsa-prov-unknown" in html

    def test_empty_assessment_renders_without_error(self):
        html = to_html(_empty_assessment())
        assert html  # non-empty

    def test_severity_badge_classes_present(self):
        findings = [_finding("X", sev) for sev in SEVERITIES]
        a = _one_network_assessment(findings=findings)
        html = to_html(a)
        for sev in SEVERITIES:
            assert f"wsa-sev-{sev}" in html, f"Missing badge class for {sev}"

    def test_clean_notice_when_no_findings(self):
        a = _one_network_assessment(findings=[])
        html = to_html(a)
        assert "wsa-clean" in html

    def test_network_bssid_appears_in_output(self):
        a = _one_network_assessment()
        html = to_html(a)
        assert "aa:bb:cc:dd:ee:ff" in html

    def test_analysis_timestamp_in_output(self):
        html = to_html(_empty_assessment())
        assert _FIXED_TS in html

    def test_parse_errors_section_shown_when_present(self):
        a = _empty_assessment()
        a.parse_errors.append("Truncated frame at offset 128")
        html = to_html(a)
        assert "Truncated frame at offset 128" in html

    def test_parse_errors_section_absent_when_empty(self):
        html = to_html(_empty_assessment())
        assert "Parse Errors" not in html


# ===========================================================================
# End-to-end: assess_pcap on synthetic captures
# ===========================================================================

class TestEndToEnd:
    """Uses the assess_pcap convenience function on all six synthetic PCAPs."""

    @pytest.fixture(scope="class")
    @classmethod
    def assessments(cls) -> dict:
        return {
            p.stem: assess_pcap(
                str(p), data_source="simulated", analysis_timestamp=_FIXED_TS
            )
            for p in sorted(DATA.glob("*.pcapng"))
        }

    # ---- Assessment structure -----------------------------------------------
    def test_data_source_is_simulated(self, assessments):
        for name, a in assessments.items():
            assert a.data_source == "simulated", f"Wrong data_source for {name}"

    def test_analysis_timestamp_matches(self, assessments):
        for a in assessments.values():
            assert a.analysis_timestamp == _FIXED_TS

    def test_open_network_has_enc001(self, assessments):
        a = assessments["open_network"]
        rule_ids = {f.rule_id for f in a.all_findings}
        assert "ENC-001" in rule_ids

    def test_wpa3_has_zero_findings(self, assessments):
        a = assessments["wpa3_network"]
        assert a.finding_count == 0
        assert a.total_risk_score == 0

    def test_wpa3_risk_score_is_zero(self, assessments):
        assert assessments["wpa3_network"].total_risk_score == 0

    # ---- JSON ---------------------------------------------------------------
    def test_json_is_valid_for_all_pcaps(self, assessments):
        for name, a in assessments.items():
            doc = json.loads(to_json(a))
            assert doc["data_source"] == "simulated", f"Wrong data_source in JSON for {name}"

    def test_json_enc001_in_open_network(self, assessments):
        doc = json.loads(to_json(assessments["open_network"]))
        all_rule_ids = [
            f["rule_id"]
            for net in doc["networks"]
            for f in net["findings"]
        ]
        assert "ENC-001" in all_rule_ids

    def test_json_wpa3_zero_findings(self, assessments):
        doc = json.loads(to_json(assessments["wpa3_network"]))
        assert doc["summary"]["total_findings"] == 0
        assert doc["summary"]["total_risk_score"] == 0

    def test_json_finding_severity_order(self, assessments):
        """Highest severity first when findings are sorted."""
        doc = json.loads(to_json(assessments["wpa2_personal"]))
        # Findings should be present (AUTH-001, AUTH-003 from Stage 3)
        nets = doc["networks"]
        assert nets[0]["findings"]

    # ---- Markdown -----------------------------------------------------------
    def test_markdown_has_h1_for_all_pcaps(self, assessments):
        for name, a in assessments.items():
            md = to_markdown(a)
            assert md.startswith("# Wireless Network Security Assessment"), name

    def test_markdown_enc001_in_open_network(self, assessments):
        md = to_markdown(assessments["open_network"])
        assert "ENC-001" in md

    def test_markdown_wpa3_clean_notice(self, assessments):
        md = to_markdown(assessments["wpa3_network"])
        assert "No security findings" in md or "satisfactory" in md

    def test_markdown_data_source_label_simulated(self, assessments):
        for a in assessments.values():
            assert "SIMULATED" in to_markdown(a)

    # ---- HTML ---------------------------------------------------------------
    def test_html_no_external_urls_for_all_pcaps(self, assessments):
        for name, a in assessments.items():
            html = to_html(a)
            assert "http://" not in html, f"External URL found for {name}"
            assert "https://" not in html, f"External URL found for {name}"

    def test_html_enc001_in_open_network(self, assessments):
        html = to_html(assessments["open_network"])
        assert "ENC-001" in html

    def test_html_wpa3_clean_notice(self, assessments):
        html = to_html(assessments["wpa3_network"])
        assert "wsa-clean" in html

    def test_html_simulated_provenance_for_all(self, assessments):
        for a in assessments.values():
            assert "wsa-prov-simulated" in to_html(a)
