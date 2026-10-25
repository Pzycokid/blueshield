"""
Run BlueShield over alert files.

    python3 -m soar.cli samples/wazuh_alerts.json samples/suricata_eve.json --out cases/
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from soar.engine import process_events, write_cases


def read_events(paths: list[Path]) -> list[dict]:
    events = []
    for p in paths:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlueShield SOAR: turn alerts into prioritised cases")
    ap.add_argument("files", nargs="+", type=Path, help="Wazuh alerts.json / Suricata eve.json files")
    ap.add_argument("--intel", type=Path, default=Path("intel"), help="folder with blocklist/allowlist/critical_assets")
    ap.add_argument("--out", type=Path, default=Path("cases"), help="where case files are written")
    args = ap.parse_args(argv)

    cases = process_events(read_events(args.files), args.intel)
    write_cases(cases, args.out)
    print(f"{len(cases)} case(s) written to {args.out}/")
    for c in cases:
        print(f"  {c[\'priority\']}  {c[\'score\']:>3}  {c[\'case_id\']}  {c[\'source_ip\'] or \'-\':<15} {c[\'summary\']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
