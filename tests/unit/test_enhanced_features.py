"""
Unit tests for enhanced assessment features:
- Station/device extraction and vendor OUI resolution
- Deep packet inspection and protocol analyzer
- Before-and-after assessment comparison
- PDF report generation
"""
from __future__ import annotations

import io
from pathlib import Path
from wsa.analysis.device_tracker import extract_stations, resolve_vendor, is_locally_administered
from wsa.analysis.protocol_analyzer import analyze_protocol_and_packets
from wsa.comparison.comparator import compare_assessments
from wsa.ingestion.pcap_reader import load_pcap
from wsa.reporting.assessment import assess_pcap
from wsa.reporting.pdf_reporter import to_pdf


def test_vendor_resolution():
    assert "Apple" in resolve_vendor("f0:18:98:12:34:56")
    assert "Raspberry Pi" in resolve_vendor("b8:27:eb:aa:bb:cc")
    assert "Intel" in resolve_vendor("00:1e:67:11:22:33")
    # Test locally administered randomized MAC
    assert is_locally_administered("02:00:00:11:22:33")
    assert "Randomized" in resolve_vendor("02:00:00:11:22:33")


def test_station_extraction_from_pcap():
    pkts, _ = load_pcap("data/simulated/open_network.pcapng")
    stations = extract_stations(pkts)
    assert isinstance(stations, list)
    for s in stations:
        data = s.to_dict()
        assert "mac" in data
        assert "vendor" in data
        assert "is_randomized" in data


def test_protocol_analyzer_from_pcap():
    pkts, _ = load_pcap("data/simulated/mixed_environment.pcapng")
    analysis = analyze_protocol_and_packets(pkts)
    assert analysis["total_packets"] == len(pkts)
    assert "categories" in analysis
    assert "management" in analysis["categories"]
    assert "samples" in analysis
    assert len(analysis["samples"]) > 0
    sample = analysis["samples"][0]
    assert "type" in sample
    assert "subtype" in sample
    assert "length" in sample


def test_before_and_after_comparison():
    baseline = assess_pcap("data/simulated/open_network.pcapng", data_source="simulated")
    target = assess_pcap("data/simulated/wpa3_network.pcapng", data_source="simulated")

    from wsa.reporting.json_reporter import _assessment_to_dict
    b_dict = _assessment_to_dict(baseline)
    t_dict = _assessment_to_dict(target)

    diff = compare_assessments(b_dict, t_dict)
    assert diff["posture"] == "IMPROVED"
    assert diff["risk_delta"] < 0
    assert diff["percentage_change"] == -100.0
    assert diff["summary"]["resolved_count"] > 0
    assert len(diff["resolved_findings"]) > 0
    assert "improved" in diff["narrative"].lower()


def test_pdf_generation_validity():
    assessment = assess_pcap("data/simulated/wpa2_personal.pcapng", data_source="simulated")
    pdf_bytes = to_pdf(assessment)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000
