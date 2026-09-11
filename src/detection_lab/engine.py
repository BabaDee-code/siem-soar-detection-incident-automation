from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


def _matches(event: dict[str, Any], conditions: dict[str, Any]) -> bool:
    for key, expected in conditions.items():
        if event.get(key) != expected:
            return False
    return True


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _largest_window(
    events: list[dict[str, Any]], window_minutes: float
) -> list[dict[str, Any]]:
    """Return the largest set of timestamped events inside a sliding window."""
    timestamped = [
        (timestamp, event)
        for event in events
        if (timestamp := _parse_timestamp(event.get("timestamp"))) is not None
    ]
    timestamped.sort(key=lambda item: item[0])

    if not timestamped:
        return []

    window = timedelta(minutes=window_minutes)
    best_start = 0
    best_end = 0
    left = 0

    for right, (right_time, _) in enumerate(timestamped):
        while right_time - timestamped[left][0] > window:
            left += 1
        if right - left > best_end - best_start:
            best_start = left
            best_end = right

    return [event for _, event in timestamped[best_start : best_end + 1]]


def detect_alerts(events: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evaluate security events against detection rules.

    Supports simple single-event rules and threshold rules grouped by a field
    such as username, source_ip, hostname, or process_name. Threshold rules may
    optionally define ``window_minutes`` to require the threshold to occur inside
    a bounded time interval.
    """
    alerts: list[dict[str, Any]] = []

    for rule in rules:
        conditions = rule.get("conditions", {})
        threshold = rule.get("threshold")
        group_by = rule.get("group_by")
        window_minutes = rule.get("window_minutes")
        matched_events = [event for event in events if _matches(event, conditions)]

        if threshold and group_by:
            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for event in matched_events:
                grouped[str(event.get(group_by, "unknown"))].append(event)

            for entity, grouped_events in grouped.items():
                qualifying_events = grouped_events
                if window_minutes is not None:
                    qualifying_events = _largest_window(grouped_events, float(window_minutes))

                if len(qualifying_events) >= int(threshold):
                    alerts.append(
                        _build_alert(
                            rule,
                            qualifying_events[0],
                            len(qualifying_events),
                            entity,
                            qualifying_events,
                        )
                    )
        else:
            for event in matched_events:
                alerts.append(
                    _build_alert(
                        rule,
                        event,
                        1,
                        str(event.get(group_by or "host", "n/a")),
                        [event],
                    )
                )

    return alerts


def _build_alert(
    rule: dict[str, Any],
    event: dict[str, Any],
    count: int,
    entity: str,
    matched_events: list[dict[str, Any]],
) -> dict[str, Any]:
    alert = {
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "mitre_attack": rule.get("mitre_attack", "unmapped"),
        "recommended_playbook": rule.get("recommended_playbook", "triage_generic_alert"),
        "entity": entity,
        "event_count": count,
        "sample_event": event,
    }

    timestamps = [
        timestamp
        for matched_event in matched_events
        if (timestamp := _parse_timestamp(matched_event.get("timestamp"))) is not None
    ]
    if timestamps:
        alert["first_seen"] = min(timestamps).isoformat().replace("+00:00", "Z")
        alert["last_seen"] = max(timestamps).isoformat().replace("+00:00", "Z")

    if rule.get("window_minutes") is not None:
        alert["detection_window_minutes"] = float(rule["window_minutes"])

    return alert
