# SIEM/SOAR Detection Engineering & Incident Automation

![CI](https://github.com/BabaDee-code/siem-soar-detection-incident-automation/actions/workflows/ci.yml/badge.svg)

A portfolio-grade detection engineering and incident automation lab that demonstrates log parsing, Sigma-inspired detection rules, MITRE ATT&CK mapping, alert enrichment, time-bounded threshold detection, severity scoring, and safe response playbook recommendations.

## What this project shows

- Detection-as-code design using YAML rules
- SIEM-style event processing and alert generation
- Time-windowed threshold detections to reduce false positives
- MITRE ATT&CK technique mapping
- Automated alert enrichment and severity scoring
- SOAR-style incident response recommendation logic
- Unit tests and CI validation for detection reliability

## Detection rule model

Rules may be single-event detections or grouped threshold detections. Threshold rules can optionally include `window_minutes`; when present, the threshold must occur within that interval rather than anywhere in the input dataset.

```yaml
id: DET-001
title: Multiple Failed Login Attempts
severity: medium
conditions:
  event_type: authentication
  outcome: failure
threshold: 3
group_by: username
window_minutes: 5
```

Windowed detections use ISO 8601 event timestamps. Events with missing or invalid timestamps do not count toward a windowed threshold. Rules without `window_minutes` retain the original count-based behavior for backward compatibility.

## Repository structure

```text
src/detection_lab/          Detection engine and CLI
rules/                      YAML detection rules
data/sample_events.jsonl    Sample security events
tests/                      Unit tests
.github/workflows/ci.yml    Automated test workflow
docs/playbooks.md           Incident response playbook mapping
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
pytest -q
PYTHONPATH=src python -m detection_lab.run data/sample_events.jsonl rules
```

On Windows PowerShell, use `$env:PYTHONPATH = "src"` before the final command.

## Example alert

```json
{
  "rule_id": "DET-001",
  "title": "Multiple Failed Login Attempts",
  "severity": "medium",
  "mitre_attack": "T1110",
  "recommended_playbook": "account_bruteforce_triage",
  "entity": "alice",
  "event_count": 3,
  "first_seen": "2026-01-01T00:00:01Z",
  "last_seen": "2026-01-01T00:00:09Z",
  "detection_window_minutes": 5.0
}
```

## Security controls represented

- Detection engineering lifecycle
- Alert triage and enrichment
- Time-bounded behavioral correlation
- MITRE ATT&CK mapping
- Incident response playbook selection
- Repeatable testing for detection quality
- Audit-ready detection documentation

## Portfolio talking points

This project demonstrates how I would build a detection engineering pipeline that is testable, explainable, and operationally useful. It shows hands-on SecOps engineering capability across SIEM content, temporal correlation, SOAR logic, incident triage, and automation.
