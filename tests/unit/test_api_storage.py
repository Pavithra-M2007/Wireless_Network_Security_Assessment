import json

from wsa.api.storage import AssessmentStore


def test_store_rejects_unsupported_capture(tmp_path):
    store = AssessmentStore(tmp_path)
    try:
        store.create("capture.txt", b"not a capture", "simulated")
    except ValueError as exc:
        assert "pcap" in str(exc).lower()
    else:
        raise AssertionError("unsupported file type was accepted")


def test_store_assesses_capture_and_persists_reports(tmp_path):
    payload = open("data/simulated/open_network.pcapng", "rb").read()
    store = AssessmentStore(tmp_path)
    record = store.create("demo.pcapng", payload, "simulated")

    assert record["data_source"] == "simulated"
    assert record["source_filename"] == "demo.pcapng"
    assert "source_file" not in record
    assert store.get_record(record["id"])["summary"]["total_networks"] >= 0
    assert {path.suffix for path in (tmp_path / "reports" / record["id"]).iterdir()} == {".json", ".md", ".html"}
    assert json.loads((tmp_path / "assessments" / f"{record['id']}.json").read_text())["data_source"] == "simulated"
