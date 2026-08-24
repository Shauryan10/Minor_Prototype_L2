from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from models.context_enriched_event import ContextEnrichedEvent
from models.security_alert import SecurityAlert

from .conditions import evaluate_condition
from .rule_schema import RuleDefinition


DEFAULT_RULES_PATH = (
    Path(__file__).resolve().parent.parent / "rules_config" / "rules.json"
)


def _to_datetime(value: str | datetime) -> datetime:
    """
    Convert an ISO timestamp into a timezone-aware datetime.
    """
    if isinstance(value, datetime):
        dt = value
    else:
        text = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def _get_nested_value(data: dict[str, Any], path: str) -> Any:
    """
    Local nested getter used for grouping.
    """
    current: Any = data

    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]

    return current


class RuleEngine:
    """
    Deterministic rule engine.

    Supports:
    - single-event conditions
    - thresholds
    - time windows
    - group_by
    - alert generation
    """

    def __init__(
        self,
        rules_path: str | Path | None = None,
    ) -> None:
        self.rules_path = Path(rules_path or DEFAULT_RULES_PATH)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[RuleDefinition]:
        if not self.rules_path.exists():
            raise FileNotFoundError(
                f"Rule configuration not found: {self.rules_path}"
            )

        with self.rules_path.open("r", encoding="utf-8") as handle:
            raw_rules = json.load(handle)

        return [RuleDefinition.model_validate(rule) for rule in raw_rules]

    @staticmethod
    def _event_to_dict(event: ContextEnrichedEvent | dict[str, Any]) -> dict[str, Any]:
        if isinstance(event, ContextEnrichedEvent):
            return event.model_dump()
        return event

    def reload(self) -> None:
        """
        Reload rules from disk without restarting the application.
        """
        self.rules = self._load_rules()

    def evaluate_event(
        self,
        event: ContextEnrichedEvent | dict[str, Any],
    ) -> list[SecurityAlert]:
        """
        Evaluate rules that operate on a single event.

        Threshold rules are intentionally handled by evaluate_events().
        """
        event_dict = self._event_to_dict(event)
        alerts: list[SecurityAlert] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Threshold rules need a collection of events.
            if rule.threshold is not None:
                continue

            if not self._conditions_match(rule, event_dict):
                continue

            if rule.action != "generate_alert":
                continue

            alerts.append(
                self._build_alert(
                    rule=rule,
                    matched_events=[event_dict],
                    triggered_conditions=self._build_triggered_conditions(
                        rule, event_dict
                    ),
                )
            )

        return alerts

    def evaluate_events(
        self,
        events: Iterable[ContextEnrichedEvent | dict[str, Any]],
    ) -> list[SecurityAlert]:
        """
        Evaluate a batch of context-enriched events.

        This supports:
        - ordinary single-event rules
        - threshold rules
        - time windows
        - group_by
        """
        event_dicts = [self._event_to_dict(event) for event in events]

        alerts: list[SecurityAlert] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.threshold is None:
                for event_dict in event_dicts:
                    if not self._conditions_match(rule, event_dict):
                        continue

                    if rule.action != "generate_alert":
                        continue

                    alerts.append(
                        self._build_alert(
                            rule=rule,
                            matched_events=[event_dict],
                            triggered_conditions=self._build_triggered_conditions(
                                rule, event_dict
                            ),
                        )
                    )

                continue

            alerts.extend(
                self._evaluate_threshold_rule(
                    rule=rule,
                    events=event_dicts,
                )
            )

        return alerts

    @staticmethod
    def _conditions_match(
        rule: RuleDefinition,
        event: dict[str, Any],
    ) -> bool:
        if not rule.conditions:
            return True

        return all(
            evaluate_condition(
                event=event,
                field=condition.field,
                operator=condition.operator,
                expected=condition.value,
            )
            for condition in rule.conditions
        )

    @staticmethod
    def _build_triggered_conditions(
        rule: RuleDefinition,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        triggered: list[dict[str, Any]] = []

        for condition in rule.conditions:
            actual = _get_nested_value(event, condition.field)

            triggered.append(
                {
                    "field": condition.field,
                    "operator": condition.operator,
                    "expected": condition.value,
                    "actual": actual,
                    "matched": evaluate_condition(
                        event=event,
                        field=condition.field,
                        operator=condition.operator,
                        expected=condition.value,
                    ),
                }
            )

        return triggered

    def _evaluate_threshold_rule(
        self,
        rule: RuleDefinition,
        events: list[dict[str, Any]],
    ) -> list[SecurityAlert]:
        """
        Threshold logic:

        Example:
        5 authentication failures
        within 5 minutes
        grouped by source IP
        """
        matching_events = [
            event
            for event in events
            if self._conditions_match(rule, event)
        ]

        if not matching_events:
            return []

        if rule.threshold is None:
            return []

        group_by = rule.group_by

        grouped: dict[Any, list[dict[str, Any]]] = {}

        if group_by:
            for event in matching_events:
                key = _get_nested_value(event, group_by)

                # Keep missing grouping values separate rather than
                # incorrectly merging unrelated events.
                key = "__missing__" if key is None else key

                grouped.setdefault(key, []).append(event)
        else:
            grouped["__all__"] = matching_events

        alerts: list[SecurityAlert] = []

        for group_key, group_events in grouped.items():
            group_events.sort(
                key=lambda event: _to_datetime(event["timestamp"])
            )

            # Without a configured window, simply apply the threshold.
            if rule.window_minutes is None:
                if len(group_events) < rule.threshold:
                    continue

                selected = group_events[-rule.threshold :]

                alerts.append(
                    self._build_alert(
                        rule=rule,
                        matched_events=selected,
                        triggered_conditions=self._build_threshold_conditions(
                            rule,
                            selected,
                            group_key,
                        ),
                    )
                )
                continue

            window = timedelta(minutes=rule.window_minutes)

            # Sliding-window evaluation.
            for index, current_event in enumerate(group_events):
                current_time = _to_datetime(current_event["timestamp"])
                window_start = current_time - window

                window_events = [
                    candidate
                    for candidate in group_events[: index + 1]
                    if window_start
                    <= _to_datetime(candidate["timestamp"])
                    <= current_time
                ]

                if len(window_events) < rule.threshold:
                    continue

                selected = window_events[-rule.threshold :]

                alerts.append(
                    self._build_alert(
                        rule=rule,
                        matched_events=selected,
                        triggered_conditions=self._build_threshold_conditions(
                            rule,
                            selected,
                            group_key,
                        ),
                    )
                )

                # Only generate the first alert for this group/window.
                break

        return alerts

    @staticmethod
    def _build_threshold_conditions(
        rule: RuleDefinition,
        events: list[dict[str, Any]],
        group_key: Any,
    ) -> list[dict[str, Any]]:
        return [
            {
                "type": "threshold",
                "threshold": rule.threshold,
                "matched_count": len(events),
                "window_minutes": rule.window_minutes,
                "group_by": rule.group_by,
                "group_value": group_key,
                "conditions": [
                    {
                        "field": condition.field,
                        "operator": condition.operator,
                        "expected": condition.value,
                    }
                    for condition in rule.conditions
                ],
            }
        ]

    @staticmethod
    def _build_alert(
        rule: RuleDefinition,
        matched_events: list[dict[str, Any]],
        triggered_conditions: list[dict[str, Any]],
    ) -> SecurityAlert:
        first_event = matched_events[0]
        last_event = matched_events[-1]

        event_ids = [
            str(event["event_id"])
            for event in matched_events
            if event.get("event_id") is not None
        ]

        evidence: list[dict[str, Any]] = []

        for event in matched_events:
            evidence.append(
                {
                    "type": "event",
                    "event_id": event.get("event_id"),
                    "timestamp": event.get("timestamp"),
                    "event_type": event.get("normalized_event", {}).get(
                        "event_type"
                    ),
                    "message": event.get("normalized_event", {}).get(
                        "message"
                    ),
                }
            )

        return SecurityAlert(
            alert_id=f"ALT-{uuid.uuid4().hex[:12].upper()}",
            event_ids=event_ids,
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            severity=rule.severity,
            confidence=rule.confidence,
            mitre_attack=rule.mitre_attack,
            entities=first_event.get("entities", {}),
            asset_context=first_event.get("asset_context", {}),
            threat_context=first_event.get("threat_context", {}),
            evidence=evidence,
            triggered_conditions=triggered_conditions,
            timestamp=last_event.get(
                "timestamp",
                datetime.now(timezone.utc).isoformat(),
            ),
            status="new",
        )