"""
fetch_findings.py

Pulls CodeQL Code Scanning alerts for a given repo from GitHub's REST API
and saves them as a clean, structured JSON file for downstream processing
(deduping, prioritization, issue creation, dashboarding).

Usage:
    export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
    python fetch_findings.py --owner <your-username> --repo juice-shop-devsecops

Docs: https://docs.github.com/en/rest/code-scanning/code-scanning
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests

API_BASE = "https://api.github.com"


def fetch_codeql_alerts(owner: str, repo: str, token: str) -> list[dict]:
    """Fetch all code scanning alerts (open + closed) for a repo, paginated."""
    alerts = []
    url = f"{API_BASE}/repos/{owner}/{repo}/code-scanning/alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {"per_page": 100, "page": 1}

    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 404:
            print(f"Error: repo '{owner}/{repo}' not found, or token lacks access.", file=sys.stderr)
            sys.exit(1)
        if resp.status_code == 403:
            print("Error: token lacks 'security_events' / 'repo' scope, or rate-limited.", file=sys.stderr)
            sys.exit(1)
        resp.raise_for_status()

        page_data = resp.json()
        if not page_data:
            break

        alerts.extend(page_data)
        params["page"] += 1

    return alerts


def normalize_alert(raw: dict) -> dict:
    """Extract just the fields we care about for triage/reporting."""
    rule = raw.get("rule", {})
    location = raw.get("most_recent_instance", {}).get("location", {})

    return {
        "id": raw.get("number"),
        "tool": "codeql",
        "rule_id": rule.get("id"),
        "description": rule.get("description"),
        "severity": rule.get("security_severity_level") or rule.get("severity"),
        "state": raw.get("state"),  # open, dismissed, fixed
        "file": location.get("path"),
        "start_line": location.get("start_line"),
        "end_line": location.get("end_line"),
        "url": raw.get("html_url"),
        "created_at": raw.get("created_at"),
    }


def main():
    parser = argparse.ArgumentParser(description="Fetch CodeQL findings from GitHub API")
    parser.add_argument("--owner", required=True, help="GitHub username/org")
    parser.add_argument("--repo", required=True, help="Repository name")
    parser.add_argument(
        "--output",
        default="findings/codeql_findings.json",
        help="Output JSON file path (default: findings/codeql_findings.json)",
    )
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: set the GITHUB_TOKEN environment variable first.", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching CodeQL alerts for {args.owner}/{args.repo} ...")
    raw_alerts = fetch_codeql_alerts(args.owner, args.repo, token)
    print(f"Fetched {len(raw_alerts)} alert(s).")

    normalized = [normalize_alert(a) for a in raw_alerts]

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(normalized, indent=2))

    print(f"Saved normalized findings to {output_path}")

    # Quick severity breakdown, useful sanity check
    counts = {}
    for f in normalized:
        sev = f["severity"] or "unknown"
        counts[sev] = counts.get(sev, 0) + 1
    print("Severity breakdown:", counts)


if __name__ == "__main__":
    main()