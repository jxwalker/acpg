#!/usr/bin/env python3
"""Evaluate ACPG compliance artifacts against a gate profile."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def count_severity(violations: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in violations:
        severity = str(item.get("severity", "")).strip().lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def add_check(checks: List[Dict[str, Any]], *, name: str, actual: Any, expected: str, ok: bool) -> None:
    checks.append(
        {
            "name": name,
            "actual": actual,
            "expected": expected,
            "pass": bool(ok),
        }
    )


def evaluate(profile_name: str, profile: Dict[str, Any], analysis: Dict[str, Any], adjudication: Dict[str, Any], trends: Dict[str, Any], dynamic_artifacts: Dict[str, Any]) -> Dict[str, Any]:
    violations = analysis.get("violations") or []
    severity = count_severity(violations)
    non_compliant = not bool(adjudication.get("compliant"))
    compliance_rate = float(trends.get("compliance_rate") or 0.0)
    avg_violations = float(trends.get("avg_violations") or 0.0)
    dynamic_issue_artifacts = int(dynamic_artifacts.get("total") or 0)

    checks: List[Dict[str, Any]] = []

    if profile.get("fail_on_non_compliant") is True:
        add_check(
            checks,
            name="adjudication_compliant",
            actual=not non_compliant,
            expected="true",
            ok=not non_compliant,
        )

    if profile.get("max_critical_violations") is not None:
        max_critical = int(profile["max_critical_violations"])
        add_check(
            checks,
            name="critical_violations",
            actual=severity["critical"],
            expected=f"<= {max_critical}",
            ok=severity["critical"] <= max_critical,
        )

    if profile.get("max_high_violations") is not None:
        max_high = int(profile["max_high_violations"])
        add_check(
            checks,
            name="high_violations",
            actual=severity["high"],
            expected=f"<= {max_high}",
            ok=severity["high"] <= max_high,
        )

    if profile.get("max_dynamic_issue_artifacts") is not None:
        max_dynamic_issues = int(profile["max_dynamic_issue_artifacts"])
        add_check(
            checks,
            name="dynamic_issue_artifacts",
            actual=dynamic_issue_artifacts,
            expected=f"<= {max_dynamic_issues}",
            ok=dynamic_issue_artifacts <= max_dynamic_issues,
        )

    if profile.get("min_compliance_rate") is not None:
        min_compliance_rate = float(profile["min_compliance_rate"])
        add_check(
            checks,
            name="compliance_rate",
            actual=round(compliance_rate, 3),
            expected=f">= {min_compliance_rate}",
            ok=compliance_rate >= min_compliance_rate,
        )

    if profile.get("max_avg_violations") is not None:
        max_avg_violations = float(profile["max_avg_violations"])
        add_check(
            checks,
            name="avg_violations",
            actual=round(avg_violations, 3),
            expected=f"<= {max_avg_violations}",
            ok=avg_violations <= max_avg_violations,
        )

    passed = all(item["pass"] for item in checks)
    enforce = bool(profile.get("enforce", True))
    status = "pass" if passed else ("fail" if enforce else "monitor_fail")

    return {
        "profile": profile_name,
        "description": profile.get("description"),
        "enforce": enforce,
        "status": status,
        "passed": passed,
        "checks": checks,
        "observations": {
            "violations_total": len(violations),
            "severity_breakdown": severity,
            "adjudication_compliant": not non_compliant,
            "compliance_rate": compliance_rate,
            "avg_violations": avg_violations,
            "dynamic_issue_artifacts": dynamic_issue_artifacts,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate ACPG CI compliance gate")
    parser.add_argument("--profiles-file", required=True, type=Path)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--analysis-file", required=True, type=Path)
    parser.add_argument("--adjudication-file", required=True, type=Path)
    parser.add_argument("--trends-file", required=True, type=Path)
    parser.add_argument("--dynamic-artifacts-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profiles_doc = load_json(args.profiles_file)
    profiles = profiles_doc.get("profiles") or {}

    selected_profile = args.profile or profiles_doc.get("default_profile")
    if selected_profile not in profiles:
        print(f"Unknown compliance profile: {selected_profile}", file=sys.stderr)
        return 2

    profile = profiles[selected_profile]
    result = evaluate(
        profile_name=selected_profile,
        profile=profile,
        analysis=load_json(args.analysis_file),
        adjudication=load_json(args.adjudication_file),
        trends=load_json(args.trends_file),
        dynamic_artifacts=load_json(args.dynamic_artifacts_file),
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"Compliance gate profile: {result['profile']} (enforce={result['enforce']})")
    for check in result["checks"]:
        prefix = "PASS" if check["pass"] else "FAIL"
        print(f"- {prefix}: {check['name']} actual={check['actual']} expected={check['expected']}")

    if result["passed"]:
        print("Compliance gate passed.")
        return 0

    if result["enforce"]:
        print("Compliance gate failed in enforce mode.", file=sys.stderr)
        return 1

    print("Compliance gate violations detected, but monitor mode is non-blocking.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
