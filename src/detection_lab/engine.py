from __future__ import annotations

from collections import defaultdict
from typing import Any


def _matches(event: dict[str, Any], conditions: dict[str, Any]) -> bool:
    for key, expected in conditions.items():
        if event.get(key) != expected:
            return False
    return True


def detect_alerts(events: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evaluate security events against detection rules.

    Supports simple single-event rules and threshold rules grouped by a field
    such as username, source_ip, hostname, or process_name.
    """
    alerts: list[dict[str, Any]] = []

    for rule in rules:
        conditions = rule.get("conditions", {})
        threshold = rule.get("threshold")
        group_by = rule.get("group_by")
        matched_events = [event for event in events if _matches(event, conditions)]

        if threshold and group_by:
            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for event in matched_events:
                grouped[str(event.get(group_by, "unknown"))].append(event)
            for entity, grouped_events in grouped.items():
                if len(grouped_events) >= int(threshold):
                    alerts.append(_build_alert(rule, grouped_events[0], len(grouped_events), entity))
        else:
            for event in matched_events:
                alerts.append(_build_alert(rule, event, 1, str(event.get(group_by or "host", "n/a"))))

    return alerts


def _build_alert(rule: dict[str, Any], event: dict[str, Any], count: int, entity: str) -> dict[str, Any]:
    return {
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "mitre_attack": rule.get("mitre_attack", "unmapped"),
        "recommended_playbook": rule.get("recommended_playbook", "triage_generic_alert"),
        "entity": entity,
        "event_count": count,
        "sample_event": event,
    }
