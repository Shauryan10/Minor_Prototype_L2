from __future__ import annotations

from typing import Any


def get_nested_value(
    data: dict[str, Any],
    path: str,
) -> Any:
    """
    Safely retrieve a nested value using dot notation.

    Example:
        get_nested_value(
            event,
            "normalized_event.source.ip"
        )
    """
    current: Any = data

    for part in path.split("."):
        if not isinstance(current, dict):
            return None

        if part not in current:
            return None

        current = current[part]

    return current


def _as_number(value: Any) -> float | None:
    """
    Convert numeric-looking values to float.
    """
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None

    return None


def evaluate_condition(
    event: dict[str, Any],
    field: str,
    operator: str,
    expected: Any,
) -> bool:
    """
    Deterministic condition evaluator.

    Supported operators:
        equals
        contains
        greater_than
        less_than
        in
    """

    actual = get_nested_value(event, field)

    if operator == "equals":
        if isinstance(actual, str) and isinstance(expected, str):
            return actual.strip().lower() == expected.strip().lower()

        return actual == expected

    if operator == "contains":
        if actual is None:
            return False

        # Handle list/set/tuple fields.
        if isinstance(actual, (list, tuple, set)):
            expected_text = str(expected).lower()

            return any(
                expected_text in str(item).lower()
                for item in actual
            )

        return str(expected).lower() in str(actual).lower()

    if operator == "greater_than":
        actual_number = _as_number(actual)
        expected_number = _as_number(expected)

        if actual_number is None or expected_number is None:
            return False

        return actual_number > expected_number

    if operator == "less_than":
        actual_number = _as_number(actual)
        expected_number = _as_number(expected)

        if actual_number is None or expected_number is None:
            return False

        return actual_number < expected_number

    if operator == "in":
        if expected is None:
            return False

        if not isinstance(expected, (list, tuple, set)):
            return False

        if isinstance(actual, str):
            return any(
                actual.lower() == str(value).lower()
                for value in expected
            )

        return actual in expected

    return False