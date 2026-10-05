from datetime import date

from check_waivers import validate

BASE = {
    "id": "W-1", "tool": "trivy", "finding": "CVE-1", "scope": "pkg", "reason": "r",
    "compensating_control": "c", "ticket": "SEC-1", "approver": "security-lead",
    "approved_on": date(2026, 10, 1), "expires_on": date(2026, 10, 20),
}


def test_valid_waiver_is_active():
    errors, active = validate([BASE], date(2026, 10, 5))
    assert errors == [] and len(active) == 1


def test_expired_waiver_fails_and_is_not_active():
    errors, active = validate([BASE], date(2026, 11, 1))
    assert any("EXPIRED" in e for e in errors) and active == []


def test_lifetime_over_30_days_rejected():
    long_lived = dict(BASE, expires_on=date(2026, 12, 1))
    errors, _ = validate([long_lived], date(2026, 10, 5))
    assert any("lifetime" in e for e in errors)


def test_non_security_approver_rejected():
    errors, _ = validate([dict(BASE, approver="random-dev")], date(2026, 10, 5))
    assert any("approver" in e for e in errors)


def test_missing_field_rejected():
    broken = {k: v for k, v in BASE.items() if k != "reason"}
    errors, _ = validate([broken], date(2026, 10, 5))
    assert any("missing" in e for e in errors)
