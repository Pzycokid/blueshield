"""
BlueShield SOAR engine.

Pipeline:  raw alert -> normalise -> enrich -> score -> correlate -> case (Markdown + JSON)

Supported inputs:
  * Wazuh alerts (alerts.json lines or the Wazuh integration webhook body)
  * Suricata alerts (eve.json lines with event_type "alert")

Design choice: BlueShield *recommends* containment actions but never executes them. A human
analyst approves every block / disable, which keeps the automation safe in a SOC.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ATT&CK technique -> recommended response steps (analyst approves each one)
PLAYBOOKS: dict[str, list[str]] = {
    "T1110": ["Block source IP at the firewall", "Check for a successful login from the same IP",
              "Enforce key-based SSH / MFA on the target"],
    "T1046": ["Confirm whether the scan source is an approved scanner",
              "Block source IP if external and unapproved", "Review which open ports were found"],
    "T1018": ["Identify the host performing discovery", "Check that host for compromise"],
    "T1059": ["Decode and review the full script block", "Check URLs / IPs in the script against threat intel",
              "Isolate the host if a payload ran"],
    "T1098": ["Verify the group change against an approved change ticket",
              "Remove the account from Administrators if unapproved"],
    "T1136": ["Verify the new account is approved", "Disable it if not"],
    "T1071": ["Look up the queried domain\'s reputation", "Block the domain at DNS / proxy if malicious"],
}
DEFAULT_ACTIONS = ["Review the raw alert and the surrounding logs", "Escalate to Tier 2 if unsure"]


@dataclass
class Alert:
    source: str                 # "wazuh" | "suricata"
    rule_id: str
    title: str
    base_severity: int          # 0-100
    timestamp: str
    src_ip: str | None = None
    host: str | None = None
    techniques: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict, repr=False)


# ---------------------------------------------------------------- normalise

def normalise(event: dict) -> Alert | None:
    """Turn a Wazuh or Suricata event into a common Alert, or None if it isn\'t an alert."""
    if "rule" in event and "level" in event.get("rule", {}):          # Wazuh
        rule = event["rule"]
        data = event.get("data", {})
        return Alert(
            source="wazuh",
            rule_id=str(rule.get("id")),
            title=rule.get("description", "Wazuh alert"),
            base_severity=round(int(rule["level"]) / 15 * 70),
            timestamp=event.get("timestamp", ""),
            src_ip=data.get("srcip") or data.get("win", {}).get("eventdata", {}).get("ipAddress"),
            host=event.get("agent", {}).get("name"),
            techniques=list(rule.get("mitre", {}).get("id", [])),
            raw=event,
        )
    if event.get("event_type") == "alert":                             # Suricata
        a = event["alert"]
        meta = a.get("metadata", {})
        return Alert(
            source="suricata",
            rule_id=str(a.get("signature_id")),
            title=a.get("signature", "Suricata alert"),
            base_severity={1: 65, 2: 45, 3: 25}.get(a.get("severity", 3), 25),
            timestamp=event.get("timestamp", ""),
            src_ip=event.get("src_ip"),
            host=event.get("dest_ip"),
            techniques=list(meta.get("mitre_technique_id", [])),
            raw=event,
        )
    return None


# ---------------------------------------------------------------- enrich

def load_list(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {l.split("#", 1)[0].strip() for l in path.read_text().splitlines() if l.split("#", 1)[0].strip()}


def abuseipdb_score(ip: str, timeout: int = 10) -> int | None:
    """Optional: AbuseIPDB confidence score (0-100). Needs ABUSEIPDB_API_KEY; returns None otherwise."""
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return None
    req = urllib.request.Request(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return int(json.load(r)["data"]["abuseConfidenceScore"])
    except Exception:
        return None


def enrich(alert: Alert, intel_dir: Path, lookup=abuseipdb_score) -> dict:
    info: dict = {"ip_type": None, "on_blocklist": False, "on_allowlist": False,
                  "abuse_score": None, "critical_asset": False}
    if alert.src_ip:
        try:
            ip = ipaddress.ip_address(alert.src_ip)
            info["ip_type"] = "private" if ip.is_private else "public"
        except ValueError:
            info["ip_type"] = "invalid"
        info["on_blocklist"] = alert.src_ip in load_list(intel_dir / "blocklist.txt")
        info["on_allowlist"] = alert.src_ip in load_list(intel_dir / "allowlist.txt")
        if info["ip_type"] == "public":
            info["abuse_score"] = lookup(alert.src_ip)
    info["critical_asset"] = bool(alert.host) and alert.host in load_list(intel_dir / "critical_assets.txt")
    return info


# ---------------------------------------------------------------- score

def score(alert: Alert, intel: dict, related_alerts: int = 0) -> tuple[int, str, list[str]]:
    """Return (score 0-100, priority P1-P4, reasons)."""
    s = alert.base_severity
    reasons = [f"base severity {alert.base_severity} from {alert.source}"]
    if intel["on_allowlist"]:
        s -= 40; reasons.append("source on allowlist (-40)")
    if intel["on_blocklist"]:
        s += 30; reasons.append("source on blocklist (+30)")
    if (intel["abuse_score"] or 0) >= 50:
        s += 20; reasons.append(f"AbuseIPDB score {intel[\'abuse_score\']} (+20)")
    if intel["critical_asset"]:
        s += 15; reasons.append("target is a critical asset (+15)")
    if related_alerts:
        bonus = min(related_alerts * 5, 20)
        s += bonus; reasons.append(f"{related_alerts} other alert(s) from same source (+{bonus})")
    s = max(0, min(100, s))
    priority = "P1" if s >= 80 else "P2" if s >= 60 else "P3" if s >= 35 else "P4"
    return s, priority, reasons


def recommended_actions(techniques: list[str]) -> list[str]:
    actions: list[str] = []
    for t in techniques:
        for step in PLAYBOOKS.get(t.split(".")[0], []):
            if step not in actions:
                actions.append(step)
    return actions or DEFAULT_ACTIONS


# ---------------------------------------------------------------- process + cases

def process_events(events: list[dict], intel_dir: Path, lookup=abuseipdb_score) -> list[dict]:
    """Normalise, enrich and score a batch, grouping alerts from the same source IP into one case."""
    alerts = [a for a in (normalise(e) for e in events) if a]
    by_src: dict[str, list[Alert]] = {}
    for a in alerts:
        by_src.setdefault(a.src_ip or f"no-ip-{a.rule_id}", []).append(a)

    cases = []
    for src, group in by_src.items():
        scored = []
        for a in group:
            intel = enrich(a, intel_dir, lookup)
            s, p, reasons = score(a, intel, related_alerts=len(group) - 1)
            scored.append((s, p, reasons, a, intel))
        scored.sort(key=lambda x: -x[0])
        top_s, top_p, top_reasons, top_a, top_intel = scored[0]
        techniques = sorted({t for *_, a, _ in scored for t in a.techniques})
        case_id = "BS-" + hashlib.sha1(f"{src}{top_a.timestamp}".encode()).hexdigest()[:8].upper()
        cases.append({
            "case_id": case_id,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "priority": top_p,
            "score": top_s,
            "source_ip": None if src.startswith("no-ip-") else src,
            "summary": top_a.title,
            "techniques": techniques,
            "score_reasons": top_reasons,
            "enrichment": top_intel,
            "recommended_actions": recommended_actions(techniques),
            "alerts": [{"source": a.source, "rule_id": a.rule_id, "title": a.title,
                        "timestamp": a.timestamp, "host": a.host, "score": s} for s, _, _, a, _ in scored],
        })
    cases.sort(key=lambda c: -c["score"])
    return cases


def case_to_markdown(case: dict) -> str:
    e = case["enrichment"]
    lines = [
        f"# {case[\'case_id\']}: {case[\'summary\']}",
        "",
        f"**Priority:** {case[\'priority\']} (score {case[\'score\']}/100)  ",
        f"**Source IP:** {case[\'source_ip\'] or \'n/a\'} ({e[\'ip_type\'] or \'n/a\'})  ",
        f"**ATT&CK:** {\', \'.join(case[\'techniques\']) or \'n/a\'}  ",
        f"**Created:** {case[\'created\']}",
        "",
        "## Why this score",
        *[f"- {r}" for r in case["score_reasons"]],
        "",
        "## Recommended actions (analyst approval required)",
        *[f"- [ ] {a}" for a in case["recommended_actions"]],
        "",
        "## Related alerts",
        "| Source | Rule | Title | Host | Time |",
        "|---|---|---|---|---|",
        *[f"| {a[\'source\']} | {a[\'rule_id\']} | {a[\'title\']} | {a[\'host\'] or \'\' } | {a[\'timestamp\']} |"
          for a in case["alerts"]],
        "",
    ]
    return "\n".join(lines)


def write_cases(cases: list[dict], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for c in cases:
        md = out_dir / f"{c[\'case_id\']}.md"
        md.write_text(case_to_markdown(c), encoding="utf-8")
        (out_dir / f"{c[\'case_id\']}.json").write_text(json.dumps(c, indent=2), encoding="utf-8")
        paths.append(md)
    return paths
