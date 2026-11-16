"""
Unit tests — wsa.analysis.beacon_extractor, feature_set, probe_extractor

Tests cover:
- Cipher / auth / MFP extraction for every synthetic PCAP scenario
- EAPOL frame count (no handshake completion claim)
- Deauth count attribution
- absent / None semantics for missing fields
- Hidden SSID and avg_rssi properties on NetworkFeatures
- ScanFeatures.network_count property
- Probe SSID extraction
"""
from __future__ import annotations

from pathlib import Path

import pytest

from wsa.analysis.beacon_extractor import extract_networks
from wsa.analysis.feature_set import (
    AUTH_OPEN, AUTH_PSK, AUTH_SAE,
    CIPHER_CCMP, CIPHER_NONE, CIPHER_WEP,
    NetworkFeatures, ScanFeatures,
)
from wsa.analysis.probe_extractor import extract_client_macs, extract_probed_ssids
from wsa.ingestion.frame_parser import parse_frames
from wsa.ingestion.pcap_reader import load_pcap

DATA = Path(__file__).parent.parent.parent / "data" / "simulated"


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

def _parsed(name: str):
    """Load a synthetic PCAP and return a ParsedFrames object."""
    pkts, _ = load_pcap(str(DATA / name))
    return parse_frames(pkts)


def _network(name: str) -> NetworkFeatures:
    """Extract the single network from a single-AP synthetic PCAP."""
    pf = _parsed(name)
    nets = extract_networks(pf.beacon_frames, pf.deauth_frames, pf.eapol_frames)
    assert len(nets) == 1, f"Expected 1 network in {name}, got {len(nets)}"
    return nets[0]


# ===========================================================================
# Open network
# ===========================================================================

class TestOpenNetwork:
    @pytest.fixture(scope="class")
    @classmethod
    def net(cls):
        return _network("open_network.pcapng")

    def test_cipher_is_none(self, net):
        assert net.cipher == CIPHER_NONE

    def test_auth_is_open(self, net):
        assert net.auth_type == AUTH_OPEN

    def test_privacy_bit_not_set(self, net):
        assert net.privacy_bit is False

    def test_no_rsn_ie_group_cipher(self, net):
        assert net.group_cipher is None

    def test_no_rsn_ie_pairwise_ciphers(self, net):
        assert net.pairwise_ciphers == []

    def test_no_rsn_ie_akm_suites(self, net):
        assert net.akm_suites == []

    def test_mfp_capable_is_none(self, net):
        """No RSN IE → MFP fields are None, not False."""
        assert net.mfp_capable is None

    def test_mfp_required_is_none(self, net):
        assert net.mfp_required is None

    def test_wps_not_present(self, net):
        assert net.wps_present is False

    def test_ssid_is_opencafe(self, net):
        assert net.ssid == "OpenCafe"

    def test_channel_is_6(self, net):
        assert net.channel == 6

    def test_bssid_is_lowercase(self, net):
        assert net.bssid == "02:aa:bb:11:22:33"

    def test_beacon_count(self, net):
        assert net.beacon_count == 10

    def test_no_deauths(self, net):
        assert net.deauth_count == 0

    def test_no_eapol(self, net):
        assert net.eapol_frame_count == 0

    def test_no_rssi_readings(self, net):
        """Synthetic RadioTap headers carry no signal data."""
        assert net.rssi_dbm == []

    def test_avg_rssi_is_none_when_no_readings(self, net):
        assert net.avg_rssi is None

    def test_hidden_ssid_false(self, net):
        assert net.hidden_ssid is False

    def test_no_wpa_versions(self, net):
        assert net.wpa_versions == []

    def test_no_parser_errors(self, net):
        assert net.parser_notes == []


# ===========================================================================
# WEP network
# ===========================================================================

class TestWepNetwork:
    @pytest.fixture(scope="class")
    @classmethod
    def net(cls):
        return _network("wep_network.pcapng")

    def test_cipher_is_wep(self, net):
        assert net.cipher == CIPHER_WEP

    def test_auth_is_open(self, net):
        """WEP has no RSN/AKM; auth summary is OPEN."""
        assert net.auth_type == AUTH_OPEN

    def test_privacy_bit_set(self, net):
        assert net.privacy_bit is True

    def test_no_rsn_ie(self, net):
        assert net.group_cipher is None
        assert net.pairwise_ciphers == []

    def test_mfp_fields_are_none(self, net):
        assert net.mfp_capable  is None
        assert net.mfp_required is None

    def test_ssid(self, net):
        assert net.ssid == "LegacyCorpNet"

    def test_channel_is_11(self, net):
        assert net.channel == 11

    def test_bssid(self, net):
        assert net.bssid == "02:aa:bb:44:55:66"

    def test_no_wpa_versions(self, net):
        assert net.wpa_versions == []


# ===========================================================================
# WPA2-Personal with WPS
# ===========================================================================

class TestWpa2PersonalWps:
    @pytest.fixture(scope="class")
    @classmethod
    def net(cls):
        return _network("wpa2_personal.pcapng")

    def test_cipher_is_ccmp(self, net):
        assert net.cipher == CIPHER_CCMP

    def test_auth_is_psk(self, net):
        assert net.auth_type == AUTH_PSK

    def test_pairwise_ciphers_contain_ccmp(self, net):
        assert CIPHER_CCMP in net.pairwise_ciphers

    def test_akm_suites_contain_psk(self, net):
        assert AUTH_PSK in net.akm_suites

    def test_mfp_capable_true(self, net):
        assert net.mfp_capable is True

    def test_mfp_required_false(self, net):
        assert net.mfp_required is False

    def test_wps_present(self, net):
        assert net.wps_present is True

    def test_ssid(self, net):
        assert net.ssid == "HomeNetwork"

    def test_channel_is_1(self, net):
        assert net.channel == 1

    def test_wpa_version_includes_wpa2(self, net):
        assert "WPA2" in net.wpa_versions

    def test_wpa3_not_claimed(self, net):
        assert "WPA3" not in net.wpa_versions

    def test_eapol_frame_count_is_4(self, net):
        """4 EAPOL frames were generated; they are counted, not a handshake claim."""
        assert net.eapol_frame_count == 4

    def test_no_handshake_attribute(self, net):
        """NetworkFeatures must NOT have a boolean has_handshake field."""
        assert not hasattr(net, "has_handshake"), (
            "Stage 2 must not claim handshake completion; "
            "use eapol_frame_count instead."
        )

    def test_bssid(self, net):
        assert net.bssid == "02:aa:bb:77:88:99"


# ===========================================================================
# WPA3-SAE with MFP Required
# ===========================================================================

class TestWpa3Network:
    @pytest.fixture(scope="class")
    @classmethod
    def net(cls):
        return _network("wpa3_network.pcapng")

    def test_cipher_is_ccmp(self, net):
        assert net.cipher == CIPHER_CCMP

    def test_auth_is_sae(self, net):
        assert net.auth_type == AUTH_SAE

    def test_akm_suites_contain_sae(self, net):
        assert AUTH_SAE in net.akm_suites

    def test_mfp_capable_true(self, net):
        assert net.mfp_capable is True

    def test_mfp_required_true(self, net):
        assert net.mfp_required is True

    def test_wps_not_present(self, net):
        assert net.wps_present is False

    def test_ssid(self, net):
        assert net.ssid == "SecureNet5G"

    def test_channel_is_36(self, net):
        assert net.channel == 36

    def test_wpa_version_includes_wpa3(self, net):
        assert "WPA3" in net.wpa_versions

    def test_wpa_version_includes_wpa2(self, net):
        """WPA3 networks still have an RSN IE (version=1), so WPA2 is also listed."""
        assert "WPA2" in net.wpa_versions

    def test_no_deauths(self, net):
        assert net.deauth_count == 0

    def test_no_eapol(self, net):
        assert net.eapol_frame_count == 0

    def test_bssid(self, net):
        assert net.bssid == "02:aa:bb:aa:bb:cc"


# ===========================================================================
# Deauth flood
# ===========================================================================

class TestDeauthFlood:
    @pytest.fixture(scope="class")
    @classmethod
    def net(cls):
        return _network("deauth_flood.pcapng")

    def test_deauth_count_is_20(self, net):
        assert net.deauth_count == 20

    def test_mfp_capable_false(self, net):
        assert net.mfp_capable is False

    def test_mfp_required_false(self, net):
        assert net.mfp_required is False

    def test_cipher_is_ccmp(self, net):
        assert net.cipher == CIPHER_CCMP

    def test_auth_is_psk(self, net):
        assert net.auth_type == AUTH_PSK

    def test_ssid(self, net):
        assert net.ssid == "TargetNetwork"

    def test_channel_is_6(self, net):
        assert net.channel == 6

    def test_no_eapol(self, net):
        assert net.eapol_frame_count == 0


# ===========================================================================
# Mixed environment (5 BSSIDs)
# ===========================================================================

class TestMixedEnvironment:
    @pytest.fixture(scope="class")
    @classmethod
    def networks(cls):
        pf = _parsed("mixed_environment.pcapng")
        return extract_networks(pf.beacon_frames, pf.deauth_frames, pf.eapol_frames)

    def test_five_unique_bssids(self, networks):
        bssids = {n.bssid for n in networks}
        assert len(bssids) == 5

    def test_open_network_present(self, networks):
        open_nets = [n for n in networks if n.cipher == CIPHER_NONE]
        assert len(open_nets) == 1

    def test_wep_network_present(self, networks):
        wep_nets = [n for n in networks if n.cipher == CIPHER_WEP]
        assert len(wep_nets) == 1

    def test_deauth_count_attributed_correctly(self, networks):
        # A broadcast deauth flood (addr1=ff:ff:ff:ff:ff:ff) with a spoofed
        # source MAC cannot be attributed to a single AP from passive observation
        # alone — the extractor conservatively attributes it to all known BSSIDs.
        # Verify: every network has deauth_count == 20 (the flood count).
        flooded = [n for n in networks if n.deauth_count > 0]
        assert len(flooded) > 0
        total_deauths = sum(n.deauth_count for n in flooded)
        # 20 deauth frames × 5 BSSIDs (broadcast attribution)
        assert total_deauths == 20 * len(flooded)
        # The "TargetNetwork" AP (deauth_flood scenario) is among the flooded.
        target = next((n for n in flooded if n.ssid == "TargetNetwork"), None)
        assert target is not None
        assert target.deauth_count == 20

    def test_eapol_attributed_to_wpa2_bssid(self, networks):
        eapol_nets = [n for n in networks if n.eapol_frame_count > 0]
        assert len(eapol_nets) == 1
        assert eapol_nets[0].eapol_frame_count == 4
        assert eapol_nets[0].ssid == "HomeNetwork"

    def test_wpa3_network_present(self, networks):
        wpa3_nets = [n for n in networks if AUTH_SAE in n.akm_suites]
        assert len(wpa3_nets) == 1

    def test_scan_features_network_count(self, networks):
        scan = ScanFeatures(
            source_file="mixed_environment.pcapng",
            data_source="simulated",
            networks=networks,
        )
        assert scan.network_count == 5


# ===========================================================================
# NetworkFeatures dataclass semantics
# ===========================================================================

class TestNetworkFeaturesSemantic:
    def test_bssid_normalised_to_lowercase(self):
        feat = NetworkFeatures(bssid="AA:BB:CC:DD:EE:FF", ssid="Test")
        assert feat.bssid == "aa:bb:cc:dd:ee:ff"

    def test_hidden_ssid_true_when_empty_string(self):
        feat = NetworkFeatures(bssid="aa:bb:cc:dd:ee:ff", ssid="")
        assert feat.hidden_ssid is True

    def test_hidden_ssid_false_when_ssid_present(self):
        feat = NetworkFeatures(bssid="aa:bb:cc:dd:ee:ff", ssid="MyNet")
        assert feat.hidden_ssid is False

    def test_hidden_ssid_false_when_ssid_none(self):
        """ssid=None means IE was absent, not that SSID was empty."""
        feat = NetworkFeatures(bssid="aa:bb:cc:dd:ee:ff", ssid=None)
        assert feat.hidden_ssid is False

    def test_avg_rssi_none_with_empty_list(self):
        feat = NetworkFeatures(bssid="aa:bb:cc:dd:ee:ff", ssid="Net")
        assert feat.avg_rssi is None

    def test_avg_rssi_computed_correctly(self):
        feat = NetworkFeatures(bssid="aa:bb:cc:dd:ee:ff", ssid="Net")
        feat.rssi_dbm = [-60, -70, -80]
        assert feat.avg_rssi == pytest.approx(-70.0)

    def test_default_eapol_count_is_zero(self):
        feat = NetworkFeatures(bssid="aa:bb:cc:dd:ee:ff", ssid="Net")
        assert feat.eapol_frame_count == 0

    def test_default_mfp_fields_are_none(self):
        feat = NetworkFeatures(bssid="aa:bb:cc:dd:ee:ff", ssid="Net")
        assert feat.mfp_capable  is None
        assert feat.mfp_required is None

    def test_default_channel_is_none(self):
        feat = NetworkFeatures(bssid="aa:bb:cc:dd:ee:ff", ssid="Net")
        assert feat.channel is None


# ===========================================================================
# Probe extractor
# ===========================================================================

class TestProbeExtractor:
    @pytest.fixture(scope="class")
    @classmethod
    def open_probes(cls):
        pf = _parsed("open_network.pcapng")
        return pf.probe_requests

    def test_extract_probed_ssids_open_network(self, open_probes):
        ssids = extract_probed_ssids(open_probes)
        assert "OpenCafe" in ssids

    def test_extract_client_macs_returns_set(self, open_probes):
        macs = extract_client_macs(open_probes)
        assert isinstance(macs, set)

    def test_extract_client_macs_count_matches_probes(self, open_probes):
        """5 probe requests; MACs may be unique or reused."""
        macs = extract_client_macs(open_probes)
        assert 1 <= len(macs) <= 5

    def test_client_macs_lowercase(self, open_probes):
        macs = extract_client_macs(open_probes)
        for mac in macs:
            assert mac == mac.lower()

    def test_empty_list_returns_empty_set(self):
        assert extract_probed_ssids([]) == set()
        assert extract_client_macs([]) == set()
