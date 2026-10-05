"""Conservative identity normalization for hybrid cloud and endpoint logs."""

from __future__ import annotations


def _user_parts(value: str | None) -> tuple[str, str, str]:
    normalized = (value or "").strip().casefold()
    if "\\" in normalized:
        _, account = normalized.rsplit("\\", 1)
        return normalized, account, "domain"
    if "@" in normalized:
        account = normalized.split("@", 1)[0]
        return normalized, account, "upn"
    return normalized, normalized, "short"


def same_identity(left: str | None, right: str | None) -> bool:
    """Match exact identities, or a short account name to a qualified account.

    Two different fully-qualified accounts never match just because their local
    portions happen to be equal.
    """
    if not left or not right:
        return False
    left_full, left_short, left_kind = _user_parts(left)
    right_full, right_short, right_kind = _user_parts(right)
    if left_full == right_full:
        return True
    can_alias = left_kind == "short" or right_kind == "short" or {left_kind, right_kind} == {"upn", "domain"}
    return can_alias and left_short == right_short


def same_entity(field: str, left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    if field == "user":
        return same_identity(left, right)
    return left.strip().rstrip(".").casefold() == right.strip().rstrip(".").casefold()
