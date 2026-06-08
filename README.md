# SIEM/SOAR Detection Engineering & Incident Automation

![CI](https://github.com/BabaDee-code/siem-soar-detection-incident-automation/actions/workflows/ci.yml/badge.svg)

A portfolio-grade detection engineering and incident automation lab that demonstrates log parsing, Sigma-inspired detection rules, MITRE ATT&CK mapping, alert enrichment, severity scoring, and safe response playbook recommendations.

## What this project shows

- Detection-as-code design using YAML rules
- SIEM-style event processing and alert generation
- MITRE ATT&CK technique mapping
- Automated alert enrichment and severity scoring
- SOAR-style incident response recommendation logic
- Unit tests and CI validation for detection reliability

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
python -m detection_lab.run data/sample_events.jsonl rules
```

## Example alert

```json
{
  "rule_id": "DET-001",
  "title": "Multiple Failed Login Attempts",
  "severity": "medium",
  "mitre_attack": "T1110",
  "recommended_playbook": "account_bruteforce_triage"
}
```

## Security controls represented

- Detection engineering lifecycle
- Alert triage and enrichment
- MITRE ATT&CK mapping
- Incident response playbook selection
- Repeatable testing for detection quality
- Audit-ready detection documentation

## Portfolio talking points

This project demonstrates how I would build a detection engineering pipeline that is testable, explainable, and operationally useful. It shows hands-on SecOps engineering capability across SIEM content, SOAR logic, incident triage, and automation.
