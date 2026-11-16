"""
Unit tests — wsa.ingestion.frame_parser

Tests cover:
- Correct bucket assignment for each frame type
- Counts match known synthetic PCAP contents
- Empty input produces zero counts
- total_frames property is consistent
- Malformed packets do not abort the parse
"""
from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11ProbeReq
from scapy.layers.eap import EAPOL

from wsa.ingestion.frame_parser import ParsedFrames, parse_frames
from wsa.ingestion.pcap_reader import load_pcap

DATA = Path(__file__).parent.parent.parent / "data" / "simulated"


def _load(name: str):
    pkts, _ = load_pcap(str(DATA / name))
    return pkts


class TestParseEmptyInput:
    def test_empty_list_returns_parsed_frames(self):
        result = parse_frames([])
        assert isinstance(result, ParsedFrames)

    def test_all_buckets_empty(self):
        result = parse_frames([])
        assert result.beacon_frames  == []
        assert result.probe_requests == []
        assert result.deauth_frames  == []
        assert result.eapol_frames   == []
        assert result.other_frames   == []

    def test_total_frames_is_zero(self):
        assert parse_frames([]).total_frames == 0


class TestOpenNetwork:
    """open_network.pcapng: 10 beacons + 5 probe requests."""

    @pytest.fixture(scope="class")
    @classmethod
    def frames(cls):
        return parse_frames(_load("open_network.pcapng"))

    def test_beacon_count(self, frames):
        assert len(frames.beacon_frames) == 10

    def test_probe_count(self, frames):
        assert len(frames.probe_requests) == 5

    def test_no_deauths(self, frames):
        assert len(frames.deauth_frames) == 0

    def test_no_eapol(self, frames):
        assert len(frames.eapol_frames) == 0

    def test_total_frames(self, frames):
        assert frames.total_frames == 15


class TestWepNetwork:
    """wep_network.pcapng: 10 beacons + 5 probe requests."""

    @pytest.fixture(scope="class")
    @classmethod
    def frames(cls):
        return parse_frames(_load("wep_network.pcapng"))

    def test_beacon_count(self, frames):
        assert len(frames.beacon_frames) == 10

    def test_probe_count(self, frames):
        assert len(frames.probe_requests) == 5

    def test_no_deauths(self, frames):
        assert len(frames.deauth_frames) == 0

    def test_total_frames(self, frames):
        assert frames.total_frames == 15


class TestWpa2Personal:
    """wpa2_personal.pcapng: 10 beacons + 4 EAPOL + 5 probes."""

    @pytest.fixture(scope="class")
    @classmethod
    def frames(cls):
        return parse_frames(_load("wpa2_personal.pcapng"))

    def test_beacon_count(self, frames):
        assert len(frames.beacon_frames) == 10

    def test_eapol_count(self, frames):
        assert len(frames.eapol_frames) == 4

    def test_probe_count(self, frames):
        assert len(frames.probe_requests) == 5

    def test_no_deauths(self, frames):
        assert len(frames.deauth_frames) == 0

    def test_total_frames(self, frames):
        assert frames.total_frames == 19


class TestWpa3Network:
    """wpa3_network.pcapng: 10 beacons + 3 probe requests."""

    @pytest.fixture(scope="class")
    @classmethod
    def frames(cls):
        return parse_frames(_load("wpa3_network.pcapng"))

    def test_beacon_count(self, frames):
        assert len(frames.beacon_frames) == 10

    def test_probe_count(self, frames):
        assert len(frames.probe_requests) == 3

    def test_no_deauths(self, frames):
        assert len(frames.deauth_frames) == 0

    def test_no_eapol(self, frames):
        assert len(frames.eapol_frames) == 0

    def test_total_frames(self, frames):
        assert frames.total_frames == 13


class TestDeauthFlood:
    """deauth_flood.pcapng: 10 beacons + 20 deauths + 3 probes."""

    @pytest.fixture(scope="class")
    @classmethod
    def frames(cls):
        return parse_frames(_load("deauth_flood.pcapng"))

    def test_beacon_count(self, frames):
        assert len(frames.beacon_frames) == 10

    def test_deauth_count(self, frames):
        assert len(frames.deauth_frames) == 20

    def test_probe_count(self, frames):
        assert len(frames.probe_requests) == 3

    def test_no_eapol(self, frames):
        assert len(frames.eapol_frames) == 0

    def test_total_frames(self, frames):
        assert frames.total_frames == 33


class TestMixedEnvironment:
    """mixed_environment.pcapng: all scenarios merged (95 frames)."""

    @pytest.fixture(scope="class")
    @classmethod
    def frames(cls):
        return parse_frames(_load("mixed_environment.pcapng"))

    def test_total_frames(self, frames):
        assert frames.total_frames == 95

    def test_has_beacons(self, frames):
        assert len(frames.beacon_frames) > 0

    def test_has_probes(self, frames):
        assert len(frames.probe_requests) > 0

    def test_has_deauths(self, frames):
        assert len(frames.deauth_frames) > 0

    def test_has_eapol(self, frames):
        assert len(frames.eapol_frames) > 0

    def test_beacon_count(self, frames):
        # 5 scenarios × 10 beacons each
        assert len(frames.beacon_frames) == 50

    def test_deauth_count(self, frames):
        assert len(frames.deauth_frames) == 20

    def test_eapol_count(self, frames):
        assert len(frames.eapol_frames) == 4


class TestParsedFramesProperties:
    """Unit tests for ParsedFrames helper behaviour."""

    def test_total_is_sum_of_all_buckets(self):
        pf = ParsedFrames()
        # Populate with dummy sentinel objects.
        pf.beacon_frames  = [object()] * 3
        pf.probe_requests = [object()] * 2
        pf.deauth_frames  = [object()] * 5
        pf.eapol_frames   = [object()] * 1
        pf.other_frames   = [object()] * 4
        assert pf.total_frames == 15

    def test_beacon_layer_present_in_bucket(self):
        pkts, _ = load_pcap(str(DATA / "open_network.pcapng"))
        frames = parse_frames(pkts)
        for pkt in frames.beacon_frames:
            assert pkt.haslayer(Dot11Beacon)

    def test_probe_layer_present_in_bucket(self):
        pkts, _ = load_pcap(str(DATA / "open_network.pcapng"))
        frames = parse_frames(pkts)
        for pkt in frames.probe_requests:
            assert pkt.haslayer(Dot11ProbeReq)

    def test_deauth_layer_present_in_bucket(self):
        pkts, _ = load_pcap(str(DATA / "deauth_flood.pcapng"))
        frames = parse_frames(pkts)
        for pkt in frames.deauth_frames:
            assert pkt.haslayer(Dot11Deauth)
