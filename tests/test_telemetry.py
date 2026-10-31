import json

from gateway.telemetry import TelemetryLog, verify_chain


def test_chain_verifies_and_resumes(tmp_path):
    path = tmp_path / "t.jsonl"
    log = TelemetryLog(path)
    for i in range(5):
        log.append({"i": i})
    assert verify_chain(path) == (True, 5, -1)
    TelemetryLog(path).append({"i": 5})  # a restarted gateway continues the same chain
    assert verify_chain(path) == (True, 6, -1)


def test_tampering_is_detected(tmp_path):
    path = tmp_path / "t.jsonl"
    log = TelemetryLog(path)
    for i in range(4):
        log.append({"decision": "BLOCKED", "i": i})
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1]); rec["decision"] = "ALLOWED"  # attacker edits a record
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    ok, n, bad = verify_chain(path)
    assert not ok and bad == 1 and n == 1


def test_deleted_record_is_detected(tmp_path):
    path = tmp_path / "t.jsonl"
    log = TelemetryLog(path)
    for i in range(4):
        log.append({"i": i})
    lines = path.read_text().splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n")
    assert verify_chain(path)[0] is False
