from detection_lab.engine import detect_alerts


def test_threshold_rule_generates_single_grouped_alert():
    events = [
        {"event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"event_type": "authentication", "outcome": "failure", "username": "alice"},
    ]
    rules = [
        {
            "id": "DET-001",
            "title": "Multiple Failed Login Attempts",
            "severity": "medium",
            "conditions": {"event_type": "authentication", "outcome": "failure"},
            "threshold": 3,
            "group_by": "username",
            "mitre_attack": "T1110",
            "recommended_playbook": "account_bruteforce_triage",
        }
    ]

    alerts = detect_alerts(events, rules)
    assert len(alerts) == 1
    assert alerts[0]["entity"] == "alice"
    assert alerts[0]["event_count"] == 3
    assert alerts[0]["mitre_attack"] == "T1110"


def test_single_event_rule_generates_alert():
    events = [{"event_type": "process", "process_name": "powershell.exe", "suspicious_flag": True, "host": "win10-01"}]
    rules = [
        {
            "id": "DET-002",
            "title": "Suspicious PowerShell Execution",
            "severity": "high",
            "conditions": {"event_type": "process", "process_name": "powershell.exe", "suspicious_flag": True},
            "mitre_attack": "T1059.001",
            "recommended_playbook": "endpoint_script_execution_triage",
        }
    ]

    alerts = detect_alerts(events, rules)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
