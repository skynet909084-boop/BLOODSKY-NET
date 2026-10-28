"""Explicit, offline release acceptance evidence. Never claims hardware validation on its own.

Usage:
    python tools/release_gate.py --template acceptance.json
    python tools/release_gate.py --check acceptance.json

A zero exit status means every listed check has an explicitly recorded pass and
nonempty sanitized evidence reference; it is NOT independent verification of a
human-authored report.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


CHECKS: tuple[tuple[str, str], ...] = (
    ("win10_installer", "Windows 10 real-PC install, launch and uninstall"),
    ("win11_installer", "Windows 11 real-PC install, launch and uninstall"),
    ("upgrade_preserves_data", "Upgrade from previous version preserves user data"),
    ("tray_autostart", "Tray, opt-in autostart and clean exit verified on real PC"),
    ("monitor_24h", "24-hour monitoring and restart behavior measured on real PC"),
    ("snmpv3_switch_a", "SNMPv3 read-only tested on physical managed switch A"),
    ("snmpv3_switch_b", "SNMPv3 read-only tested on a different switch vendor"),
    ("lldp_fdb_vlan", "LLDP/FDB/VLAN compared to known physical network"),
    ("wifi_dhcp", "Wi-Fi and local DHCP read-only behavior verified on Windows"),
    ("security_privacy", "Logs and exports checked for secrets and unexpected network writes"),
    ("release_authenticity", "Installer signer or explicit unsigned distribution notice reviewed"),
    ("probe_two_real_pcs", "Pinned TLS transfer between separate real Windows PCs"),
    ("probe_identity_revoke", "Per-sender revocation and unauthorized replay verified on real PCs"),
    ("probe_outage_recovery", "20-minute outage and recovery measured between two real PCs"),
)

VALID_STATES = frozenset({"not_run", "pass", "fail", "blocked"})


def template() -> dict:
    """Every acceptance criterion begins as unverified, never as a passing claim."""
    return {
        "schema_version": 1,
        "target_version": "1.0.0",
        "checks": [
            {"id": key, "status": "not_run", "environment": "", "evidence": ""}
            for key, _ in CHECKS
        ],
    }


def evaluate(report: object) -> tuple[bool, list[str]]:
    """Evaluate supplied manual evidence; never run scans or touch credentials."""
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("Expected release-gate schema_version=1")
    if report.get("target_version") != "1.0.0":
        raise ValueError("Release acceptance must target exactly 1.0.0")
    checks = report.get("checks")
    if not isinstance(checks, list):
        raise ValueError("checks must be an array")
    seen: set[str] = set()
    known = {name for name, _ in CHECKS}
    missing_or_failed: list[str] = []
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("Invalid check entry")
        key, status = check.get("id"), check.get("status")
        if not isinstance(key, str) or key not in known or key in seen:
            raise ValueError("Duplicate or unknown check identifier")
        if status not in VALID_STATES:
            raise ValueError("Invalid check state")
        seen.add(key)
        if status == "pass":
            # An explicit description and evidence pointer are required for a
            # human-reviewed pass, but do not independently prove testing.
            if not isinstance(check.get("environment"), str) or not check["environment"].strip():
                missing_or_failed.append(f"{key}: missing test environment")
            if not isinstance(check.get("evidence"), str) or not check["evidence"].strip():
                missing_or_failed.append(f"{key}: missing evidence reference")
        else:
            missing_or_failed.append(f"{key}: {status}")
    for key, _ in CHECKS:
        if key not in seen:
            missing_or_failed.append(f"{key}: absent")
    return not missing_or_failed, missing_or_failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BLOODSKY NET 1.0 offline hardware acceptance gate")
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--template", metavar="FILE", help="write unverified JSON template (fails if file exists)")
    operations.add_argument("--check", metavar="FILE", help="evaluate manually completed JSON evidence")
    args = parser.parse_args(argv)
    try:
        if args.template:
            path = Path(args.template)
            with path.open("x", encoding="utf-8") as handle:
                json.dump(template(), handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            print("Created unverified acceptance template:", path)
            return 0
        with Path(args.check).open(encoding="utf-8") as handle:
            report = json.load(handle)
        ready, reasons = evaluate(report)
        if ready:
            print("All acceptance entries reported PASS with environment and evidence references.")
            print("Human verification of the evidence is still required before 1.0 release.")
            return 0
        print("BLOCKED: Windows/hardware 1.0 acceptance incomplete")
        for issue in reasons:
            print(" -", issue)
        return 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Invalid acceptance report:", type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
