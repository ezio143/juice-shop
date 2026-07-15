"""
prioritize.py

Takes normalized findings (from fetch_findings.py, or eventually Snyk/ZAP
equivalents) and:
  1. Groups them by rule_id (the actual "issue type"), collapsing repeated
     instances of the same rule into one entry with an occurrence list.
  2. Sorts groups by severity, then by occurrence count (most widespread
     first within a severity tier).
  3. Prints a readable summary and writes a structured JSON report.

Usage:
    python prioritize.py --input findings/codeql_findings.json
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def load_findings(path: Path) -> list[dict]:
    if not path.exists():
        print(f"Error: input file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text())


def group_by_rule(findings: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for f in findings:
        groups[f["rule_id"]].append(f)

    grouped = []
    for rule_id, instances in groups.items():
        # All instances of a rule should share severity/description; take from the first.
        first = instances[0]
        grouped.append({
            "rule_id": rule_id,
            "description": first["description"],
            "severity": (first.get("severity") or "unknown").lower(),
            "tool": first["tool"],
            "occurrence_count": len(instances),
            "locations": [
                {"file": i["file"], "start_line": i["start_line"], "end_line": i["end_line"], "url": i["url"]}
                for i in instances
            ],
        })

    grouped.sort(
        key=lambda g: (SEVERITY_ORDER.get(g["severity"], 4), -g["occurrence_count"])
    )
    return grouped


def print_summary(grouped: list[dict]) -> None:
    print(f"\n{'SEVERITY':<10} {'COUNT':<7} {'RULE':<45} DESCRIPTION")
    print("-" * 110)
    for g in grouped:
        print(f"{g['severity'].upper():<10} {g['occurrence_count']:<7} {g['rule_id']:<45} {g['description']}")

    total_findings = sum(g["occurrence_count"] for g in grouped)
    print("-" * 110)
    print(f"{len(grouped)} distinct issue type(s) across {total_findings} total finding(s)\n")


def main():
    parser = argparse.ArgumentParser(description="Dedupe and prioritize security findings")
    parser.add_argument("--input", required=True, help="Path to normalized findings JSON")
    parser.add_argument(
        "--output",
        default="findings/prioritized_report.json",
        help="Output path for the grouped/prioritized JSON report",
    )
    args = parser.parse_args()

    findings = load_findings(Path(args.input))
    grouped = group_by_rule(findings)

    print_summary(grouped)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(grouped, indent=2))
    print(f"Full prioritized report saved to {output_path}")


if __name__ == "__main__":
    main()