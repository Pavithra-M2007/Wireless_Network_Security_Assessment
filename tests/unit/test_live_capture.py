from __future__ import annotations

from wsa.api.live_lab import LiveLab, diagnostics


def test_diagnostics_reports_kernel_and_capture_capability() -> None:
    result = diagnostics()
    assert "kernel" in result
    assert "mac80211_hwsim" in result
    assert "interfaces" in result
    assert "capture_ready" in result


def test_live_start_is_truthful_when_no_interface_is_available(monkeypatch) -> None:
    monkeypatch.setattr("wsa.api.live_lab.diagnostics", lambda: {"interfaces": [], "blocker": "test blocker"})
    state = LiveLab().start("normal")
    assert state["status"] == "error"
    assert state["packets"] == 0
    assert state["networks"] == []
    assert state["findings"] == []
    assert state["risk_score"] == 0
    assert "test blocker" in state["error"]


def test_live_capture_lifecycle_does_not_fabricate_packets(monkeypatch) -> None:
    monkeypatch.setattr("wsa.api.live_lab.diagnostics", lambda: {"interfaces": [{"name": "wlan-test", "type": "monitor"}], "blocker": None})
    monkeypatch.setattr(LiveLab, "_capture_loop", lambda self: None)
    lab = LiveLab()
    state = lab.start("normal", "wlan-test")
    assert state["status"] == "capturing"
    assert state["capture_interface"] == "wlan-test"
    assert state["packets"] == 0
    stopped = lab.stop()
    assert stopped["status"] == "stopped"
    assert stopped["packets"] == 0
    assert stopped["findings"] == []
