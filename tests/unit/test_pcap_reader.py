"""
Unit tests — wsa.ingestion.pcap_reader

Tests cover:
- Successful load of each synthetic PCAP
- FileNotFoundError for missing files
- PcapReadError for empty files
- Return types and warning list behaviour
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from wsa.ingestion.pcap_reader import PcapReadError, load_pcap

# Path to synthetic test data (Stage 1 output).
DATA = Path(__file__).parent.parent.parent / "data" / "simulated"


class TestLoadPcapSuccess:
    """Happy-path tests using the Stage 1 synthetic captures."""

    def test_open_network_loads(self):
        pkts, warnings = load_pcap(str(DATA / "open_network.pcapng"))
        assert len(pkts) == 15
        assert warnings == []

    def test_wep_network_loads(self):
        pkts, warnings = load_pcap(str(DATA / "wep_network.pcapng"))
        assert len(pkts) == 15
        assert warnings == []

    def test_wpa2_personal_loads(self):
        pkts, warnings = load_pcap(str(DATA / "wpa2_personal.pcapng"))
        assert len(pkts) == 19
        assert warnings == []

    def test_wpa3_network_loads(self):
        pkts, warnings = load_pcap(str(DATA / "wpa3_network.pcapng"))
        assert len(pkts) == 13
        assert warnings == []

    def test_deauth_flood_loads(self):
        pkts, warnings = load_pcap(str(DATA / "deauth_flood.pcapng"))
        assert len(pkts) == 33
        assert warnings == []

    def test_mixed_environment_loads(self):
        pkts, warnings = load_pcap(str(DATA / "mixed_environment.pcapng"))
        assert len(pkts) == 95
        assert warnings == []

    def test_returns_list(self):
        pkts, _ = load_pcap(str(DATA / "open_network.pcapng"))
        assert isinstance(pkts, list)

    def test_warnings_is_list(self):
        _, warnings = load_pcap(str(DATA / "open_network.pcapng"))
        assert isinstance(warnings, list)


class TestLoadPcapErrors:
    """Error-handling tests."""

    def test_missing_file_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_pcap("/nonexistent/path/capture.pcapng")

    def test_missing_file_message_contains_path(self):
        path = "/nonexistent/path/capture.pcapng"
        with pytest.raises(FileNotFoundError, match=path):
            load_pcap(path)

    def test_empty_file_raises_pcap_read_error(self):
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            tmp_path = f.name  # written nothing → 0 bytes
        try:
            with pytest.raises(PcapReadError, match="empty"):
                load_pcap(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_non_pcap_file_raises_pcap_read_error(self):
        with tempfile.NamedTemporaryFile(
            suffix=".pcapng", delete=False, mode="wb"
        ) as f:
            f.write(b"this is not a valid pcap file\n" * 10)
            tmp_path = f.name
        try:
            with pytest.raises(PcapReadError):
                load_pcap(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_pcap_read_error_is_exception(self):
        assert issubclass(PcapReadError, Exception)
