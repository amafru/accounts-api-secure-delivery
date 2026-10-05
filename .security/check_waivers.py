#!/usr/bin/env python3
"""Validate the waiver register and emit a .trivyignore of ACTIVE waivers only.

Threat mapping: [T1] supply chain (CVE waivers must expire), [T2] pipeline (the gate
cannot be silently disabled).  Exit code 1 means the build must fail.
"""
import sys
from datetime import date, timedelta
from pathlib import Path

import yaml

REQUIRED = [
    "id", "tool", "finding", "scope", "reason", "compensating_control",
    "ticket", "approver", "approved_on", "expires_on",
]
MAX_DAYS = 30
APPROVERS = {"security-lead", "security-deputy"}  # mirror of the CODEOWNERS security team


def to_date(value):
    if isinstance(value, date):
        return value
    else:
        return date.fromisoformat(str(value))


def validate(waivers, today):
    """Return (errors, active) for a list of waiver dicts."""
    errors = []
    active = []
    for entry in waivers:
        label = entry.get("id", "<no id>")
        missing = [f for f in REQUIRED if not entry.get(f)]
        if missing:
            errors.append(f"{label}: missing fields {missing}")
            continue
        else:
            pass
        approved = to_date(entry["approved_on"])
        expires = to_date(entry["expires_on"])
        if entry["approver"] not in APPROVERS:
            errors.append(f"{label}: approver {entry['approver']!r} is not a security reviewer")
        else:
            pass
        if expires - approved > timedelta(days=MAX_DAYS):
            errors.append(f"{label}: lifetime exceeds {MAX_DAYS} days")
        else:
            pass
        if expires < today:
            errors.append(f"{label}: EXPIRED on {expires}, renew with fresh approval or fix the finding")
        else:
            active.append(entry)
    return errors, active


def main(path="waivers.yaml", out=".trivyignore", today=None):
    today = today or date.today()
    data = yaml.safe_load(Path(path).read_text()) or {}
    errors, active = validate(data.get("waivers", []), today)
    trivy_ids = [w["finding"] for w in active if w["tool"] == "trivy"]
    Path(out).write_text("\n".join(trivy_ids) + ("\n" if trivy_ids else ""))
    for message in errors:
        print(f"WAIVER ERROR: {message}")
    print(f"{len(active)} active waiver(s), {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
