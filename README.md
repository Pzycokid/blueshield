# BlueShield: Detection-as-Code & SOAR Lab

BlueShield is the automation layer of my home SOC. It does two jobs:

1. **Detection-as-Code.** Detection rules live in Git as [Sigma](https://github.com/SigmaHQ/sigma).
   Every push runs CI that validates the rules and converts them to Splunk SPL and Elastic queries,
   so detections are reviewed, versioned and tested like software.
2. **SOAR (Security Orchestration, Automation and Response).** Alerts from
   [Wazuh](https://github.com/Pzycokid/wazuh-soc-lab) and [Suricata](https://github.com/Pzycokid/suricata-ids-lab)
   are normalised, enriched with threat intel, scored, correlated by source IP, and turned into
   prioritised case files with ATT&CK-mapped response steps.

> **Human in the loop:** BlueShield *recommends* containment (block IP, disable account, isolate
> host) but never executes it. An analyst approves every action, which keeps automation from
> blocking the wrong thing.

## Architecture

```mermaid
flowchart LR
    subgraph Sources
        WZ["Wazuh SIEM<br/>alerts.json / webhook"]
        SU["Suricata IDS<br/>eve.json"]
    end
    subgraph SOAR["BlueShield SOAR (soar/)"]
        N["Normalise"] --> E["Enrich<br/>blocklist · allowlist<br/>critical assets · AbuseIPDB"]
        E --> S["Score 0-100<br/>P1-P4"]
        S --> C["Correlate by source IP"]
        C --> K["Case file<br/>Markdown + JSON"]
    end
    WZ --> N
    SU --> N
    K --> A["Analyst approves<br/>recommended actions"]
    subgraph DaC["Detection-as-Code (detections/)"]
        R["Sigma rules"] --> CI["GitHub Actions<br/>sigma check + convert"]
        CI --> Q["Splunk / Elastic queries"]
    end
```

## Example: brute force followed by a successful login

Input: two Wazuh alerts from [`samples/wazuh_alerts.json`](samples/wazuh_alerts.json), a brute
force (rule 100100) and then a successful login from the same IP (rule 100101).

```
$ python3 -m soar.cli samples/wazuh_alerts.json samples/suricata_eve.json --out cases
5 case(s) written to cases/
  P1  100  BS-A2DA2C93  203.0.113.50    Possible compromise: successful SSH login from 203.0.113.50 after brute force
  P1  100  BS-1371E225  10.0.0.66       LAB POLICY Telnet connection to internal host
  P1   80  BS-9A06BE33  10.0.0.77       LAB CRED Possible SSH brute force
  P3   56  BS-A529A8F8  -               Suspicious PowerShell script block (download cradle or encoded command)
  P3   45  BS-A62853F7  192.168.56.10   LAB DNS Query to commonly abused TLD
```

Each case explains its score and lists the next steps, for example:

```
## Why this score
- base severity 61 from wazuh
- source on blocklist (+30)
- target is a critical asset (+15)
- 1 other alert(s) from same source (+5)

## Recommended actions (analyst approval required)
- [ ] Block source IP at the firewall
- [ ] Check for a successful login from the same IP
- [ ] Enforce key-based SSH / MFA on the target
```

## Scoring model

| Factor | Effect |
|---|---|
| Base severity | Wazuh level scaled to 0–70; Suricata severity 1/2/3 → 65/45/25 |
| Source IP on `intel/blocklist.txt` | +30 |
| AbuseIPDB confidence ≥ 50 (optional, needs `ABUSEIPDB_API_KEY`) | +20 |
| Target in `intel/critical_assets.txt` | +15 |
| Other alerts from the same source in the batch | +5 each (max +20) |
| Source IP on `intel/allowlist.txt` | −40 |

Priority: **P1** ≥ 80 · **P2** ≥ 60 · **P3** ≥ 35 · **P4** below.

## Usage

```bash
git clone https://github.com/Pzycokid/blueshield.git && cd blueshield
python3 -m soar.cli samples/wazuh_alerts.json samples/suricata_eve.json --out cases
python3 -m pytest -q                              # tests
```

**Real-time mode:** run `python3 -m soar.webhook --port 8088` and point a Wazuh integration at
`http://<host>:8088/alert`. Each alert becomes a case as it arrives. Keep it on the lab network;
the receiver has no authentication.

**Detections:** add a rule to `detections/sigma/` and push. The `detections-ci` workflow validates
it and publishes the converted Splunk and Elastic queries as a build artifact.

## Repository layout

```
blueshield/
├── detections/sigma/        # Sigma rules (detection-as-code)
├── soar/engine.py           # normalise, enrich, score, correlate, cases
├── soar/cli.py              # batch mode
├── soar/webhook.py          # real-time receiver for Wazuh
├── intel/                   # blocklist, allowlist, critical assets
├── samples/                 # sample Wazuh and Suricata alerts
├── tests/                   # pytest
└── .github/workflows/ci.yml # Sigma validation + conversion, SOAR tests
```

## Roadmap

- [x] Sigma detection-as-code with CI validation and Splunk / Elastic conversion
- [x] SOAR engine: normalise, enrich, score, correlate, case files
- [x] Real-time webhook for Wazuh
- [ ] Pull new-host findings from [attack-surface-monitor](https://github.com/Pzycokid/attack-surface-monitor)
- [ ] Optional approved-action mode (e.g. push an approved IP block to a firewall API)
- [ ] Case metrics: time to triage, alerts per source, false-positive rate

## Author

**Likhith H S**, M.Sc. Cyber Security, NFSU Goa · CEH · CCNA ·
[LinkedIn](https://www.linkedin.com/in/LikhithHS15)
