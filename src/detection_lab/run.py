from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from .engine import detect_alerts


def load_events(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def load_rules(path: str) -> list[dict]:
    rules = []
    for rule_path in sorted(Path(path).glob("*.yml")):
        rules.append(yaml.safe_load(rule_path.read_text(encoding="utf-8")))
    return rules


def main(events_path: str, rules_path: str) -> None:
    alerts = detect_alerts(load_events(events_path), load_rules(rules_path))
    print(json.dumps(alerts, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python -m detection_lab.run data/sample_events.jsonl rules")
    main(sys.argv[1], sys.argv[2])
