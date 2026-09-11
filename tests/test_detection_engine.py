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


def test_time_window_threshold_alerts_when_events_are_close_together():
    events = [
        {"timestamp": "2026-01-01T00:00:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T00:02:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T00:04:59Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
    ]
    rules = [
        {
            "id": "DET-001",
            "title": "Multiple Failed Login Attempts",
            "severity": "medium",
            "conditions": {"event_type": "authentication", "outcome": "failure"},
            "threshold": 3,
            "group_by": "username",
            "window_minutes": 5,
        }
    ]

    alerts = detect_alerts(events, rules)
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 3
    assert alerts[0]["first_seen"] == "2026-01-01T00:00:00Z"
    assert alerts[0]["last_seen"] == "2026-01-01T00:04:59Z"
    assert alerts[0]["detection_window_minutes"] == 5.0


def test_time_window_threshold_ignores_events_spread_too_far_apart():
    events = [
        {"timestamp": "2026-01-01T00:00:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T00:10:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T00:20:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
    ]
    rules = [
        {
            "id": "DET-001",
            "title": "Multiple Failed Login Attempts",
            "severity": "medium",
            "conditions": {"event_type": "authentication", "outcome": "failure"},
            "threshold": 3,
            "group_by": "username",
            "window_minutes": 5,
        }
    ]

    assert detect_alerts(events, rules) == []


def test_time_window_threshold_uses_largest_qualifying_cluster():
    events = [
        {"timestamp": "2026-01-01T00:00:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T01:00:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T01:01:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T01:02:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T01:03:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
    ]
    rules = [
        {
            "id": "DET-001",
            "title": "Multiple Failed Login Attempts",
            "severity": "medium",
            "conditions": {"event_type": "authentication", "outcome": "failure"},
            "threshold": 3,
            "group_by": "username",
            "window_minutes": 5,
        }
    ]

    alerts = detect_alerts(events, rules)
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 4
    assert alerts[0]["first_seen"] == "2026-01-01T01:00:00Z"
    assert alerts[0]["last_seen"] == "2026-01-01T01:03:00Z"


def test_invalid_or_missing_timestamps_do_not_satisfy_windowed_threshold():
    events = [
        {"timestamp": "not-a-date", "event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"event_type": "authentication", "outcome": "failure", "username": "alice"},
        {"timestamp": "2026-01-01T00:00:00Z", "event_type": "authentication", "outcome": "failure", "username": "alice"},
    ]
    rules = [
        {
            "id": "DET-001",
            "title": "Multiple Failed Login Attempts",
            "severity": "medium",
            "conditions": {"event_type": "authentication", "outcome": "failure"},
            "threshold": 3,
            "group_by": "username",
            "window_minutes": 5,
        }
    ]

    assert detect_alerts(events, rules) == []


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
