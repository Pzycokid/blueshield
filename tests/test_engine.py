import json
import threading
import urllib.request
from pathlib import Path

import pytest

from soar import cli
from soar.engine import (Alert, case_to_markdown, enrich, normalise, process_events,
                         recommended_actions, score)
from soar.webhook import serve

ROOT = Path(__file__).resolve().parent.parent
INTEL = ROOT / "intel"
SAMPLES = ROOT / "samples"


def no_lookup(ip):
    return None


def load(name):
    return [json.loads(l) for l in (SAMPLES / name).read_text(encoding="utf-8").splitlines() if l.strip()]


def all_events():
    return load("wazuh_alerts.json") + load("suricata_eve.json")


# ---------------------------------------------------------------- normalise

def test_normalise_wazuh():
    a = normalise(load("wazuh_alerts.json")[0])
    assert a.source == "wazuh"
    assert a.rule_id == "100100"
    assert a.src_ip == "203.0.113.50"
    assert a.host == "srv-web01"
    assert a.techniques == ["T1110.001"]
    assert a.base_severity == round(10 / 15 * 70)


def test_normalise_suricata():
    a = normalise(load("suricata_eve.json")[3])
    assert a.source == "suricata"
    assert a.rule_id == "1000010"
    assert a.base_severity == 65          # severity 1
    assert a.src_ip == "10.0.0.77"
    assert a.techniques == ["T1110"]


def test_non_alert_events_are_ignored():
    dns_event = load("suricata_eve.json")[-1]
    assert dns_event["event_type"] == "dns"
    assert normalise(dns_event) is None
    assert normalise({"foo": "bar"}) is None


# ---------------------------------------------------------------- enrich + score

def test_enrich_flags_blocklist_and_critical_asset():
    a = normalise(load("wazuh_alerts.json")[0])
    intel = enrich(a, INTEL, no_lookup)
    assert intel["ip_type"] == "public"
    assert intel["on_blocklist"] is True
    assert intel["critical_asset"] is True


def test_allowlisted_scanner_is_downgraded():
    a = normalise(load("wazuh_alerts.json")[4])
    intel = enrich(a, INTEL, no_lookup)
    s, p, reasons = score(a, intel)
    assert intel["on_allowlist"] is True
    assert p == "P4"
    assert any("allowlist" in r for r in reasons)


def test_abuseipdb_bonus_is_applied():
    a = Alert(source="suricata", rule_id="1", title="t", base_severity=45, timestamp="",
              src_ip="198.51.100.9", host="10.9.9.9")
    intel = enrich(a, INTEL, lookup=lambda ip: 90)
    s, _, reasons = score(a, intel)
    assert s == 65
    assert any("AbuseIPDB" in r for r in reasons)


def test_score_is_clamped_and_priorities():
    a = Alert(source="wazuh", rule_id="1", title="t", base_severity=95, timestamp="")
    intel = {"on_allowlist": False, "on_blocklist": True, "abuse_score": 99, "critical_asset": True}
    s, p, _ = score(a, intel, related_alerts=10)
    assert s == 100 and p == "P1"


def test_recommended_actions_use_parent_technique():
    actions = recommended_actions(["T1110.001"])
    assert "Block source IP at the firewall" in actions
    assert recommended_actions(["T9999"])[0].startswith("Review the raw alert")


# ---------------------------------------------------------------- correlation + cases

def test_alerts_from_same_source_become_one_case():
    cases = process_events(all_events(), INTEL, no_lookup)
    by_src = {c["source_ip"]: c for c in cases}
    assert len(by_src["203.0.113.50"]["alerts"]) == 2          # brute force + successful login
    assert len(by_src["10.0.0.66"]["alerts"]) == 3             # SYN scan + XMAS scan + Telnet
    assert by_src["203.0.113.50"]["priority"] == "P1"
    assert by_src["192.168.56.5"]["priority"] == "P4"          # allowlisted scanner


def test_cases_sorted_by_score_and_ids_are_stable():
    first = process_events(all_events(), INTEL, no_lookup)
    second = process_events(all_events(), INTEL, no_lookup)
    assert [c["score"] for c in first] == sorted((c["score"] for c in first), reverse=True)
    assert [c["case_id"] for c in first] == [c["case_id"] for c in second]


def test_markdown_case_contains_reasons_and_actions():
    case = process_events(all_events(), INTEL, no_lookup)[0]
    md = case_to_markdown(case)
    assert md.startswith(f"# {case['case_id']}")
    assert "## Why this score" in md
    assert "- [ ] " in md


def test_cli_writes_case_files(tmp_path, capsys):
    rc = cli.main([str(SAMPLES / "wazuh_alerts.json"), str(SAMPLES / "suricata_eve.json"),
                   "--intel", str(INTEL), "--out", str(tmp_path)])
    assert rc == 0
    assert len(list(tmp_path.glob("BS-*.md"))) == len(list(tmp_path.glob("BS-*.json"))) == 7
    assert "7 case(s) written" in capsys.readouterr().out


# ---------------------------------------------------------------- webhook

@pytest.fixture
def server(tmp_path):
    httpd = serve("127.0.0.1", 0, INTEL, tmp_path)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", tmp_path
    httpd.shutdown()
    httpd.server_close()


def post(url, body: bytes):
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_webhook_creates_case(server):
    base, out = server
    with urllib.request.urlopen(base + "/health", timeout=5) as r:
        assert json.load(r) == {"status": "ok"}
    status, body = post(base + "/alert", json.dumps(load("wazuh_alerts.json")[1]).encode())
    assert status == 200
    assert body["cases"][0]["priority"] == "P1"
    assert (out / f"{body['cases'][0]['case_id']}.md").exists()


def test_webhook_rejects_bad_json(server):
    base, _ = server
    status, body = post(base + "/alert", b"not json")
    assert status == 400 and body["error"] == "invalid JSON"
