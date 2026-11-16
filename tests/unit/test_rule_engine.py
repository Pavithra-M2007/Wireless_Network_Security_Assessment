"""
Unit tests — Stage 3: rule engine, loader, evaluator, and Finding model.

Test coverage:
  - Finding dataclass structure and severity constants
  - RuleLoadError / ConditionError hierarchy
  - YAML loader: valid files, malformed YAML, missing keys, invalid severity,
    unknown operator, empty file
  - Condition evaluator: every operator including compound operators,
    identity checks for None/True/False, numeric safety with None fields
  - Rule engine: per-rule firing and non-firing for all 9 rules across all
    network types; heuristic threshold boundary conditions; absent-evidence
    safety; malformed-YAML resilience
  - End-to-end: findings derived from Stage 2 output on the 6 synthetic PCAPs
"""
from __future__ import annotations

import textwrap
import tempfile
from pathlib import Path
from typing import List, Set

import pytest

from wsa.analysis.feature_set import (
    AUTH_EAP, AUTH_OPEN, AUTH_PSK, AUTH_SAE,
    CIPHER_CCMP, CIPHER_GCMP, CIPHER_MIXED, CIPHER_NONE,
    CIPHER_TKIP, CIPHER_UNKNOWN, CIPHER_WEP,
    NetworkFeatures, ScanFeatures,
)
from wsa.analysis.beacon_extractor import extract_networks
from wsa.ingestion.frame_parser import parse_frames
from wsa.ingestion.pcap_reader import load_pcap
from wsa.rules import (
    ConditionError, Finding, RuleEngine, RuleLoadError,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_INFO,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_ORDER,
    VALID_SEVERITIES, evaluate_condition,
    load_rules_from_dir, load_rules_from_file,
)

DATA     = Path(__file__).parent.parent.parent / "data" / "simulated"
RULES_DIR = Path(__file__).parent.parent.parent / "rules"


# ===========================================================================
# Helpers
# ===========================================================================

def net(**kwargs) -> NetworkFeatures:
    """Build a NetworkFeatures with safe WPA2 defaults; override via kwargs."""
    defaults: dict = dict(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="TestNet",
        cipher=CIPHER_CCMP,
        auth_type=AUTH_PSK,
        mfp_capable=True,
        mfp_required=True,
        wps_present=False,
        deauth_count=0,
        privacy_bit=True,
    )
    defaults.update(kwargs)
    return NetworkFeatures(**defaults)


def rule_ids(findings: List[Finding]) -> Set[str]:
    return {f.rule_id for f in findings}


def _load_pcap_scan(name: str) -> tuple:
    """Load a synthetic PCAP and return (ParsedFrames, List[NetworkFeatures])."""
    pkts, _ = load_pcap(str(DATA / name))
    pf = parse_frames(pkts)
    networks = extract_networks(pf.beacon_frames, pf.deauth_frames, pf.eapol_frames)
    return pf, networks


# ===========================================================================
# Finding dataclass
# ===========================================================================

class TestFindingDataclass:
    def test_finding_is_frozen(self):
        f = Finding(
            rule_id="TST-001", category="Test", severity=SEVERITY_HIGH,
            title="T", explanation="E", impact="I", remediation="R",
            evidence="x = 1", bssid="aa:bb:cc:dd:ee:ff", ssid="Net",
        )
        with pytest.raises((TypeError, AttributeError)):
            f.rule_id = "changed"  # type: ignore[misc]

    def test_finding_has_all_fields(self):
        f = Finding(
            rule_id="TST-001", category="Encryption", severity=SEVERITY_CRITICAL,
            title="Open", explanation="No enc", impact="Bad", remediation="Fix",
            evidence="cipher = 'NONE'", bssid="aa:bb:cc:dd:ee:ff", ssid="Open",
        )
        assert f.rule_id    == "TST-001"
        assert f.category   == "Encryption"
        assert f.severity   == SEVERITY_CRITICAL
        assert f.title      == "Open"
        assert f.bssid      == "aa:bb:cc:dd:ee:ff"
        assert f.ssid       == "Open"

    def test_severity_order_critical_lt_info(self):
        assert SEVERITY_ORDER[SEVERITY_CRITICAL] < SEVERITY_ORDER[SEVERITY_INFO]

    def test_severity_order_high_lt_medium(self):
        assert SEVERITY_ORDER[SEVERITY_HIGH] < SEVERITY_ORDER[SEVERITY_MEDIUM]

    def test_valid_severities_contains_five(self):
        assert len(VALID_SEVERITIES) == 5

    def test_finding_severity_order_property(self):
        f = Finding(
            rule_id="X", category="Y", severity=SEVERITY_CRITICAL,
            title="T", explanation="", impact="", remediation="",
            evidence="", bssid="aa:bb:cc:dd:ee:ff", ssid=None,
        )
        assert f.severity_order == 0  # CRITICAL = 0

    def test_rule_load_error_is_value_error(self):
        assert issubclass(RuleLoadError, ValueError)

    def test_condition_error_is_value_error(self):
        assert issubclass(ConditionError, ValueError)


# ===========================================================================
# YAML Loader
# ===========================================================================

class TestLoader:
    def test_loads_rules_from_real_dir(self):
        rules = load_rules_from_dir(RULES_DIR)
        assert len(rules) >= 9  # 4 enc + 3 auth + 2 dos

    def test_all_loaded_rules_have_required_keys(self):
        rules = load_rules_from_dir(RULES_DIR)
        required = {"id", "category", "severity", "title", "condition",
                    "evidence_field", "explanation", "impact", "remediation"}
        for r in rules:
            assert required <= r.keys(), f"Rule {r.get('id')} missing keys"

    def test_all_loaded_severities_valid(self):
        rules = load_rules_from_dir(RULES_DIR)
        for r in rules:
            assert r["severity"] in VALID_SEVERITIES, \
                f"Rule {r['id']} has invalid severity {r['severity']!r}"

    def test_missing_rules_dir_raises(self, tmp_path):
        with pytest.raises(RuleLoadError, match="does not exist"):
            load_rules_from_dir(tmp_path / "nonexistent")

    def test_malformed_yaml_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules:\n  - {unclosed: [bracket\n")
        with pytest.raises(RuleLoadError, match="YAML parse error"):
            load_rules_from_file(bad)

    def test_missing_rules_key_raises(self, tmp_path):
        f = tmp_path / "norules.yaml"
        f.write_text("something: else\n")
        with pytest.raises(RuleLoadError, match="missing required top-level key 'rules'"):
            load_rules_from_file(f)

    def test_missing_rule_field_raises(self, tmp_path):
        f = tmp_path / "missing_field.yaml"
        f.write_text(textwrap.dedent("""
            rules:
              - id: BAD-001
                category: Test
                severity: HIGH
                title: Missing fields
        """))
        with pytest.raises(RuleLoadError, match="missing required key"):
            load_rules_from_file(f)

    def test_invalid_severity_raises(self, tmp_path):
        f = tmp_path / "bad_severity.yaml"
        f.write_text(textwrap.dedent("""
            rules:
              - id: BAD-001
                category: Test
                severity: EXTREME
                title: Bad severity
                evidence_field: cipher
                explanation: x
                impact: y
                remediation: z
                condition:
                  op: eq
                  field: cipher
                  value: "NONE"
        """))
        with pytest.raises(RuleLoadError, match="invalid severity"):
            load_rules_from_file(f)

    def test_unknown_operator_in_yaml_raises(self, tmp_path):
        f = tmp_path / "bad_op.yaml"
        f.write_text(textwrap.dedent("""
            rules:
              - id: BAD-001
                category: Test
                severity: HIGH
                title: Bad op
                evidence_field: cipher
                explanation: x
                impact: y
                remediation: z
                condition:
                  op: regex_match
                  field: cipher
        """))
        with pytest.raises(RuleLoadError, match="unknown operator"):
            load_rules_from_file(f)

    def test_empty_file_returns_no_rules(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("")
        assert load_rules_from_file(f) == []

    def test_compound_missing_conditions_raises(self, tmp_path):
        f = tmp_path / "bad_compound.yaml"
        f.write_text(textwrap.dedent("""
            rules:
              - id: BAD-002
                category: Test
                severity: LOW
                title: Bad compound
                evidence_field: cipher
                explanation: x
                impact: y
                remediation: z
                condition:
                  op: all_of
        """))
        with pytest.raises(RuleLoadError, match="non-empty 'conditions'"):
            load_rules_from_file(f)


# ===========================================================================
# Condition Evaluator — operator-by-operator
# ===========================================================================

class TestEvaluatorSimpleOps:
    def _net(self, **kwargs) -> NetworkFeatures:
        return net(**kwargs)

    # ---- eq / ne -----------------------------------------------------------
    def test_eq_true(self):
        n = self._net(cipher=CIPHER_NONE)
        assert evaluate_condition({"op": "eq", "field": "cipher", "value": "NONE"}, n)

    def test_eq_false(self):
        n = self._net(cipher=CIPHER_CCMP)
        assert not evaluate_condition({"op": "eq", "field": "cipher", "value": "NONE"}, n)

    def test_ne_true(self):
        n = self._net(cipher=CIPHER_CCMP)
        assert evaluate_condition({"op": "ne", "field": "cipher", "value": "NONE"}, n)

    def test_ne_false(self):
        n = self._net(cipher=CIPHER_NONE)
        assert not evaluate_condition({"op": "ne", "field": "cipher", "value": "NONE"}, n)

    # ---- is_true / is_false / is_none / is_not_none -------------------------
    def test_is_true_with_true(self):
        assert evaluate_condition({"op": "is_true", "field": "wps_present"}, net(wps_present=True))

    def test_is_true_with_false(self):
        assert not evaluate_condition({"op": "is_true", "field": "wps_present"}, net(wps_present=False))

    def test_is_true_with_none(self):
        """is_true must not match None (absent evidence must not trigger rules)."""
        assert not evaluate_condition({"op": "is_true", "field": "mfp_capable"}, net(mfp_capable=None))

    def test_is_false_with_false(self):
        assert evaluate_condition({"op": "is_false", "field": "mfp_capable"}, net(mfp_capable=False))

    def test_is_false_with_true(self):
        assert not evaluate_condition({"op": "is_false", "field": "mfp_capable"}, net(mfp_capable=True))

    def test_is_false_with_none(self):
        """is_false must not match None — preserves absent-evidence safety."""
        assert not evaluate_condition({"op": "is_false", "field": "mfp_capable"}, net(mfp_capable=None))

    def test_is_none_with_none(self):
        assert evaluate_condition({"op": "is_none", "field": "mfp_capable"}, net(mfp_capable=None))

    def test_is_none_with_value(self):
        assert not evaluate_condition({"op": "is_none", "field": "mfp_capable"}, net(mfp_capable=False))

    def test_is_not_none_with_value(self):
        assert evaluate_condition({"op": "is_not_none", "field": "mfp_capable"}, net(mfp_capable=False))

    def test_is_not_none_with_none(self):
        assert not evaluate_condition({"op": "is_not_none", "field": "mfp_capable"}, net(mfp_capable=None))

    # ---- Numeric -----------------------------------------------------------
    def test_gte_true(self):
        n = net(deauth_count=10)
        assert evaluate_condition({"op": "gte", "field": "deauth_count", "value": 10}, n)

    def test_gte_false(self):
        n = net(deauth_count=9)
        assert not evaluate_condition({"op": "gte", "field": "deauth_count", "value": 10}, n)

    def test_lt_true(self):
        n = net(deauth_count=5)
        assert evaluate_condition({"op": "lt", "field": "deauth_count", "value": 10}, n)

    def test_lt_false(self):
        n = net(deauth_count=10)
        assert not evaluate_condition({"op": "lt", "field": "deauth_count", "value": 10}, n)

    def test_gte_with_none_field_is_false(self):
        """Numeric op on a None field must not raise; returns False."""
        n = net(mfp_capable=None)
        assert not evaluate_condition({"op": "gte", "field": "mfp_capable", "value": 1}, n)

    # ---- in / not_in -------------------------------------------------------
    def test_in_true(self):
        n = net(cipher=CIPHER_WEP)
        cond = {"op": "in", "field": "cipher", "value": ["NONE", "WEP"]}
        assert evaluate_condition(cond, n)

    def test_in_false(self):
        n = net(cipher=CIPHER_CCMP)
        cond = {"op": "in", "field": "cipher", "value": ["NONE", "WEP"]}
        assert not evaluate_condition(cond, n)

    def test_not_in_true(self):
        n = net(cipher=CIPHER_CCMP)
        cond = {"op": "not_in", "field": "cipher", "value": ["NONE", "WEP"]}
        assert evaluate_condition(cond, n)

    # ---- contains ----------------------------------------------------------
    def test_contains_true(self):
        n = net()
        n.pairwise_ciphers.append(CIPHER_TKIP)
        cond = {"op": "contains", "field": "pairwise_ciphers", "value": CIPHER_TKIP}
        assert evaluate_condition(cond, n)

    def test_contains_false(self):
        n = net()
        cond = {"op": "contains", "field": "pairwise_ciphers", "value": CIPHER_TKIP}
        assert not evaluate_condition(cond, n)

    def test_not_contains_true(self):
        n = net()  # pairwise_ciphers is empty by default
        cond = {"op": "not_contains", "field": "pairwise_ciphers", "value": CIPHER_TKIP}
        assert evaluate_condition(cond, n)

    # ---- Unknown operator --------------------------------------------------
    def test_unknown_op_raises_condition_error(self):
        n = net()
        with pytest.raises(ConditionError, match="Unknown operator"):
            evaluate_condition({"op": "regex_match", "field": "cipher", "value": ".*"}, n)

    def test_unknown_field_raises_condition_error(self):
        n = net()
        with pytest.raises(ConditionError, match="no field"):
            evaluate_condition({"op": "eq", "field": "nonexistent_field", "value": "x"}, n)


class TestEvaluatorCompoundOps:
    def test_all_of_both_true(self):
        n = net(mfp_capable=True, mfp_required=False)
        cond = {"op": "all_of", "conditions": [
            {"op": "is_true",  "field": "mfp_capable"},
            {"op": "is_false", "field": "mfp_required"},
        ]}
        assert evaluate_condition(cond, n)

    def test_all_of_one_false(self):
        n = net(mfp_capable=True, mfp_required=True)
        cond = {"op": "all_of", "conditions": [
            {"op": "is_true",  "field": "mfp_capable"},
            {"op": "is_false", "field": "mfp_required"},
        ]}
        assert not evaluate_condition(cond, n)

    def test_any_of_one_true(self):
        n = net(cipher=CIPHER_CCMP, wps_present=True)
        cond = {"op": "any_of", "conditions": [
            {"op": "eq",      "field": "cipher", "value": "NONE"},
            {"op": "is_true", "field": "wps_present"},
        ]}
        assert evaluate_condition(cond, n)

    def test_any_of_all_false(self):
        n = net(cipher=CIPHER_CCMP, wps_present=False)
        cond = {"op": "any_of", "conditions": [
            {"op": "eq",      "field": "cipher", "value": "NONE"},
            {"op": "is_true", "field": "wps_present"},
        ]}
        assert not evaluate_condition(cond, n)

    def test_none_of_all_false(self):
        n = net(cipher=CIPHER_CCMP, wps_present=False)
        cond = {"op": "none_of", "conditions": [
            {"op": "eq",      "field": "cipher", "value": "NONE"},
            {"op": "is_true", "field": "wps_present"},
        ]}
        assert evaluate_condition(cond, n)

    def test_none_of_one_true(self):
        n = net(cipher=CIPHER_NONE, wps_present=False)
        cond = {"op": "none_of", "conditions": [
            {"op": "eq",      "field": "cipher", "value": "NONE"},
            {"op": "is_true", "field": "wps_present"},
        ]}
        assert not evaluate_condition(cond, n)

    def test_empty_conditions_raises(self):
        with pytest.raises(ConditionError):
            evaluate_condition({"op": "all_of", "conditions": []}, net())


# ===========================================================================
# Rule Engine — per-rule firing and non-firing
# ===========================================================================

class TestEngineEncryptionRules:
    @pytest.fixture(scope="class")
    @classmethod
    def engine(cls):
        return RuleEngine(RULES_DIR)

    def test_enc001_fires_for_open(self, engine):
        assert "ENC-001" in rule_ids(engine.evaluate_network(net(cipher=CIPHER_NONE, mfp_capable=None, mfp_required=None, privacy_bit=False, auth_type=AUTH_OPEN)))

    def test_enc001_does_not_fire_for_wpa2(self, engine):
        assert "ENC-001" not in rule_ids(engine.evaluate_network(net()))

    def test_enc002_fires_for_wep(self, engine):
        assert "ENC-002" in rule_ids(engine.evaluate_network(net(cipher=CIPHER_WEP, mfp_capable=None, mfp_required=None, auth_type=AUTH_OPEN, privacy_bit=True)))

    def test_enc002_does_not_fire_for_ccmp(self, engine):
        assert "ENC-002" not in rule_ids(engine.evaluate_network(net()))

    def test_enc003_fires_for_tkip(self, engine):
        assert "ENC-003" in rule_ids(engine.evaluate_network(net(cipher=CIPHER_TKIP)))

    def test_enc003_does_not_fire_for_ccmp(self, engine):
        assert "ENC-003" not in rule_ids(engine.evaluate_network(net()))

    def test_enc004_fires_for_mixed(self, engine):
        assert "ENC-004" in rule_ids(engine.evaluate_network(net(cipher=CIPHER_MIXED)))

    def test_enc004_does_not_fire_for_ccmp(self, engine):
        assert "ENC-004" not in rule_ids(engine.evaluate_network(net()))

    def test_unknown_cipher_triggers_no_enc_rule(self, engine):
        """An UNKNOWN cipher means evidence is insufficient — no finding raised."""
        n = net(cipher=CIPHER_UNKNOWN)
        ids = rule_ids(engine.evaluate_network(n))
        assert not any(rid.startswith("ENC-") for rid in ids), \
            f"ENC rule fired on UNKNOWN cipher: {ids}"


class TestEngineAuthRules:
    @pytest.fixture(scope="class")
    @classmethod
    def engine(cls):
        return RuleEngine(RULES_DIR)

    # AUTH-001: WPS
    def test_auth001_fires_for_wps(self, engine):
        assert "AUTH-001" in rule_ids(engine.evaluate_network(net(wps_present=True)))

    def test_auth001_does_not_fire_without_wps(self, engine):
        assert "AUTH-001" not in rule_ids(engine.evaluate_network(net(wps_present=False)))

    # AUTH-002: No MFP (RSN IE present, both bits False)
    def test_auth002_fires_for_no_mfp(self, engine):
        n = net(mfp_capable=False, mfp_required=False)
        assert "AUTH-002" in rule_ids(engine.evaluate_network(n))

    def test_auth002_does_not_fire_for_absent_rsn(self, engine):
        """mfp_capable=None means no RSN IE — must not trigger AUTH-002."""
        n = net(mfp_capable=None, mfp_required=None, cipher=CIPHER_NONE, auth_type=AUTH_OPEN)
        assert "AUTH-002" not in rule_ids(engine.evaluate_network(n))

    def test_auth002_does_not_fire_when_capable_true(self, engine):
        n = net(mfp_capable=True, mfp_required=False)
        assert "AUTH-002" not in rule_ids(engine.evaluate_network(n))

    def test_auth002_does_not_fire_when_required_true(self, engine):
        n = net(mfp_capable=True, mfp_required=True)
        assert "AUTH-002" not in rule_ids(engine.evaluate_network(n))

    # AUTH-003: MFP optional (capable but not required)
    def test_auth003_fires_for_mfp_optional(self, engine):
        n = net(mfp_capable=True, mfp_required=False)
        assert "AUTH-003" in rule_ids(engine.evaluate_network(n))

    def test_auth003_does_not_fire_when_mfp_required(self, engine):
        n = net(mfp_capable=True, mfp_required=True)
        assert "AUTH-003" not in rule_ids(engine.evaluate_network(n))

    def test_auth003_does_not_fire_when_not_capable(self, engine):
        n = net(mfp_capable=False, mfp_required=False)
        assert "AUTH-003" not in rule_ids(engine.evaluate_network(n))

    def test_auth003_does_not_fire_for_absent_rsn(self, engine):
        n = net(mfp_capable=None, mfp_required=None, cipher=CIPHER_NONE, auth_type=AUTH_OPEN)
        assert "AUTH-003" not in rule_ids(engine.evaluate_network(n))


class TestEngineDosRules:
    @pytest.fixture(scope="class")
    @classmethod
    def engine(cls):
        return RuleEngine(RULES_DIR)

    # DOS-001: >= 10
    def test_dos001_fires_at_threshold(self, engine):
        assert "DOS-001" in rule_ids(engine.evaluate_network(net(deauth_count=10)))

    def test_dos001_fires_above_threshold(self, engine):
        assert "DOS-001" in rule_ids(engine.evaluate_network(net(deauth_count=20)))

    def test_dos001_does_not_fire_below_threshold(self, engine):
        assert "DOS-001" not in rule_ids(engine.evaluate_network(net(deauth_count=9)))

    def test_dos001_does_not_fire_at_zero(self, engine):
        assert "DOS-001" not in rule_ids(engine.evaluate_network(net(deauth_count=0)))

    # DOS-002: 3 <= count < 10
    def test_dos002_fires_at_lower_threshold(self, engine):
        assert "DOS-002" in rule_ids(engine.evaluate_network(net(deauth_count=3)))

    def test_dos002_fires_in_range(self, engine):
        assert "DOS-002" in rule_ids(engine.evaluate_network(net(deauth_count=7)))

    def test_dos002_does_not_fire_below_lower(self, engine):
        assert "DOS-002" not in rule_ids(engine.evaluate_network(net(deauth_count=2)))

    def test_dos002_does_not_fire_at_or_above_upper(self, engine):
        """count=10 triggers DOS-001, not DOS-002 (exclusive upper bound)."""
        assert "DOS-002" not in rule_ids(engine.evaluate_network(net(deauth_count=10)))

    def test_dos002_does_not_fire_at_zero(self, engine):
        assert "DOS-002" not in rule_ids(engine.evaluate_network(net(deauth_count=0)))

    # Boundary values at DOS-001 exactly-at-threshold vs DOS-002
    def test_exactly_9_triggers_dos002_not_dos001(self, engine):
        n = net(deauth_count=9)
        ids = rule_ids(engine.evaluate_network(n))
        assert "DOS-002" in ids
        assert "DOS-001" not in ids

    def test_exactly_10_triggers_dos001_not_dos002(self, engine):
        n = net(deauth_count=10)
        ids = rule_ids(engine.evaluate_network(n))
        assert "DOS-001" in ids
        assert "DOS-002" not in ids


class TestEngineEdgeCases:
    @pytest.fixture(scope="class")
    @classmethod
    def engine(cls):
        return RuleEngine(RULES_DIR)

    def test_perfect_wpa3_network_has_no_findings(self, engine):
        """SAE + MFP required + no WPS + no deauths → clean bill of health."""
        n = net(
            cipher=CIPHER_CCMP,
            auth_type=AUTH_SAE,
            mfp_capable=True,
            mfp_required=True,
            wps_present=False,
            deauth_count=0,
        )
        assert engine.evaluate_network(n) == []

    def test_finding_evidence_contains_field_name(self, engine):
        n = net(cipher=CIPHER_NONE, mfp_capable=None, mfp_required=None,
                auth_type=AUTH_OPEN, privacy_bit=False)
        findings = engine.evaluate_network(n)
        enc_finding = next(f for f in findings if f.rule_id == "ENC-001")
        assert "cipher" in enc_finding.evidence

    def test_finding_bssid_matches_network(self, engine):
        n = net(bssid="de:ad:be:ef:00:01", cipher=CIPHER_NONE,
                mfp_capable=None, mfp_required=None, auth_type=AUTH_OPEN, privacy_bit=False)
        findings = engine.evaluate_network(n)
        for f in findings:
            assert f.bssid == "de:ad:be:ef:00:01"

    def test_finding_ssid_matches_network(self, engine):
        n = net(ssid="MyNet", cipher=CIPHER_NONE, mfp_capable=None,
                mfp_required=None, auth_type=AUTH_OPEN, privacy_bit=False)
        findings = engine.evaluate_network(n)
        for f in findings:
            assert f.ssid == "MyNet"

    def test_engine_with_empty_rules_dir(self, tmp_path):
        """Engine with no YAML files returns empty findings, no error."""
        empty_engine = RuleEngine(tmp_path)
        assert empty_engine.rules == []
        assert empty_engine.evaluate_network(net()) == []

    def test_engine_missing_rules_dir_raises(self):
        with pytest.raises(RuleLoadError):
            RuleEngine("/nonexistent/rules/dir")

    def test_evaluate_scan_returns_pairs(self, engine):
        scan = ScanFeatures(source_file="test.pcapng", data_source="simulated")
        scan.networks.append(net())
        results = engine.evaluate_scan(scan)
        assert len(results) == 1
        network_obj, findings_list = results[0]
        assert isinstance(network_obj, NetworkFeatures)
        assert isinstance(findings_list, list)

    def test_finding_explanation_not_empty(self, engine):
        n = net(cipher=CIPHER_NONE, mfp_capable=None, mfp_required=None,
                auth_type=AUTH_OPEN, privacy_bit=False)
        findings = engine.evaluate_network(n)
        for f in findings:
            assert f.explanation.strip(), f"Empty explanation for {f.rule_id}"
            assert f.impact.strip(), f"Empty impact for {f.rule_id}"
            assert f.remediation.strip(), f"Empty remediation for {f.rule_id}"


# ===========================================================================
# End-to-end tests using Stage 2 output on synthetic PCAPs
# ===========================================================================

class TestEndToEnd:
    @pytest.fixture(scope="class")
    @classmethod
    def engine(cls):
        return RuleEngine(RULES_DIR)

    def _findings_for(self, engine, pcap_name: str) -> List[Finding]:
        _, networks = _load_pcap_scan(pcap_name)
        all_findings = []
        for n in networks:
            all_findings.extend(engine.evaluate_network(n))
        return all_findings

    def test_open_network_triggers_enc001(self, engine):
        findings = self._findings_for(engine, "open_network.pcapng")
        assert "ENC-001" in rule_ids(findings), \
            f"Expected ENC-001 for open network; got {rule_ids(findings)}"

    def test_open_network_does_not_trigger_enc002(self, engine):
        findings = self._findings_for(engine, "open_network.pcapng")
        assert "ENC-002" not in rule_ids(findings)

    def test_wep_network_triggers_enc002(self, engine):
        findings = self._findings_for(engine, "wep_network.pcapng")
        assert "ENC-002" in rule_ids(findings)

    def test_wep_network_does_not_trigger_enc001(self, engine):
        findings = self._findings_for(engine, "wep_network.pcapng")
        assert "ENC-001" not in rule_ids(findings)

    def test_wpa2_personal_triggers_auth001_wps(self, engine):
        findings = self._findings_for(engine, "wpa2_personal.pcapng")
        assert "AUTH-001" in rule_ids(findings)

    def test_wpa2_personal_triggers_auth003_mfp_optional(self, engine):
        findings = self._findings_for(engine, "wpa2_personal.pcapng")
        assert "AUTH-003" in rule_ids(findings)

    def test_wpa2_personal_does_not_trigger_enc001_or_enc002(self, engine):
        findings = self._findings_for(engine, "wpa2_personal.pcapng")
        assert "ENC-001" not in rule_ids(findings)
        assert "ENC-002" not in rule_ids(findings)

    def test_wpa2_personal_does_not_trigger_auth002(self, engine):
        """mfp_capable=True for wpa2_personal — AUTH-002 must not fire."""
        findings = self._findings_for(engine, "wpa2_personal.pcapng")
        assert "AUTH-002" not in rule_ids(findings)

    def test_wpa3_network_has_zero_findings(self, engine):
        """Perfect WPA3 config: SAE, MFP required, no WPS, no deauths."""
        findings = self._findings_for(engine, "wpa3_network.pcapng")
        assert findings == [], \
            f"Expected 0 findings for WPA3; got {[f.rule_id for f in findings]}"

    def test_deauth_flood_triggers_dos001(self, engine):
        findings = self._findings_for(engine, "deauth_flood.pcapng")
        assert "DOS-001" in rule_ids(findings)

    def test_deauth_flood_triggers_auth002_no_mfp(self, engine):
        """deauth_flood scenario has mfp_capable=False → AUTH-002 should fire."""
        findings = self._findings_for(engine, "deauth_flood.pcapng")
        assert "AUTH-002" in rule_ids(findings)

    def test_deauth_flood_does_not_trigger_dos002(self, engine):
        """20 deauths → DOS-001, not DOS-002 (count >= 10)."""
        findings = self._findings_for(engine, "deauth_flood.pcapng")
        assert "DOS-002" not in rule_ids(findings)

    def test_mixed_environment_contains_enc001_and_enc002(self, engine):
        """Mixed capture has both open and WEP networks."""
        findings = self._findings_for(engine, "mixed_environment.pcapng")
        ids = rule_ids(findings)
        assert "ENC-001" in ids
        assert "ENC-002" in ids

    def test_mixed_environment_contains_dos001(self, engine):
        findings = self._findings_for(engine, "mixed_environment.pcapng")
        assert "DOS-001" in rule_ids(findings)

    def test_all_findings_have_non_empty_evidence(self, engine):
        for pcap in DATA.glob("*.pcapng"):
            findings = self._findings_for(engine, pcap.name)
            for f in findings:
                assert f.evidence.strip(), \
                    f"Empty evidence in {f.rule_id} from {pcap.name}"

    def test_enc001_finding_severity_is_critical(self, engine):
        findings = self._findings_for(engine, "open_network.pcapng")
        enc001 = next(f for f in findings if f.rule_id == "ENC-001")
        assert enc001.severity == SEVERITY_CRITICAL

    def test_auth001_finding_severity_is_high(self, engine):
        findings = self._findings_for(engine, "wpa2_personal.pcapng")
        auth001 = next(f for f in findings if f.rule_id == "AUTH-001")
        assert auth001.severity == SEVERITY_HIGH
