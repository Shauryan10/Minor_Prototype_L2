from __future__ import annotations

from typing import Any


def get_nested_value(
    data: dict[str, Any],
    path: str,
) -> Any:
    current: Any = data

    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None

        current = current[part]

    return current


def evaluate_condition(
    event: dict[str, Any],
    field: str,
    operator: str,
    expected: Any,
) -> bool:
    actual = get_nested_value(event, field)

    if operator == "equals":
        return actual == expected

    if operator == "contains":
        if actual is None:
            return False

        return str(expected).lower() in str(actual).lower()

    if operator == "greater_than":
        if actual is None:
            return False

        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False

    if operator == "less_than":
        if actual is None:
            return False

        try:
            return float(actual) < float(expected)
        except (TypeError, ValueError):
            return False

    if operator == "in":
        if expected is None:
            return False

        return actual in expected

    return False