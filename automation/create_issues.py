"""
create_issues.py

Reads the prioritized/grouped findings report (from prioritize.py) and
auto-creates a GitHub Issue for each CRITICAL-severity rule group that
doesn't already have an open issue for it.

One issue per rule_id (not per raw finding) — the issue body lists every
affected file/line so nothing is lost, but the noisy 1-alert-per-line
problem doesn't carry over into the Issues tab.

Usage:
    export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
    python create_issues.py --owner <you> --repo juice-shop-devsecops \
        --input findings/prioritized_report.json --severity critical
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests

API_BASE = "https://api.github.com"
ISSUE_MARKER = "<!-- automated-security-finding -->"


def load_report(path: Path) -> list[dict]:
    if not path.exists():
        print(f"Error: input file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text())


def get_existing_rule_ids(owner: str, repo: str, headers: dict) -> set[str]:
    """
    Fetch rule_ids already covered by an open issue, by scanning ALL open
    issues (no label pre-filter, since a missing/mismatched label would
    silently break duplicate detection) and pulling the rule_id out of the
    issue body marker line.
    """
    rule_ids = set()
    url = f"{API_BASE}/repos/{owner}/{repo}/issues"
    params = {"state": "open", "per_page": 100, "page": 1}

    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        page_data = resp.json()
        if not page_data:
            break
        for issue in page_data:
            body = issue.get("body") or ""
            if ISSUE_MARKER in body:
                for line in body.splitlines():
                    if line.startswith("**Rule:**"):
                        # line looks like: **Rule:** `js/code-injection`
                        rid = line.split("`")[1] if "`" in line else None
                        if rid:
                            rule_ids.add(rid)
                        break
        params["page"] += 1

    # print(f"Debug: found {len(rule_ids)} existing automated issue(s) already open: {rule_ids}")
    return rule_ids


def build_issue_body(group: dict) -> str:
    locations_md = "\n".join(
        f"- `{loc['file']}:{loc['start_line']}` — [view finding]({loc['url']})"
        for loc in group["locations"]
    )
    return (
        f"{ISSUE_MARKER}\n\n"
        f"**Tool:** {group['tool']}\n"
        f"**Severity:** {group['severity'].upper()}\n"
        f"**Rule:** `{group['rule_id']}`\n"
        f"**Occurrences:** {group['occurrence_count']}\n\n"
        f"### Description\n{group['description']}\n\n"
        f"### Affected locations\n{locations_md}\n\n"
        f"---\n*This issue was auto-created from the security pipeline's prioritized findings report.*"
    )


def create_issue(owner: str, repo: str, headers: dict, group: dict) -> None:
    title = f"[{group['severity'].upper()}] {group['rule_id']}: {group['description']}"
    url = f"{API_BASE}/repos/{owner}/{repo}/issues"
    payload = {
        "title": title,
        "body": build_issue_body(group),
        "labels": ["security-automated", group["severity"], group["tool"]],
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    if resp.status_code == 201:
        issue_url = resp.json()["html_url"]
        print(f"Created: {title}\n  -> {issue_url}")
    else:
        print(f"Failed to create issue for '{title}': {resp.status_code} {resp.text}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Auto-create GitHub Issues for critical findings")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--input", default="findings/prioritized_report.json")
    parser.add_argument(
        "--severity",
        default="critical",
        choices=["critical", "high", "medium"],
        help="Only create issues for groups at or above this severity (default: critical only)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be created without actually calling the GitHub API",
    )
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: set the GITHUB_TOKEN environment variable first.", file=sys.stderr)
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    grouped = load_report(Path(args.input))
    target_groups = [g for g in grouped if g["severity"] == args.severity]

    if not target_groups:
        print(f"No '{args.severity}' severity groups found in {args.input}. Nothing to do.")
        return

    print(f"Found {len(target_groups)} '{args.severity}' issue type(s) to process.")


    existing_rule_ids = get_existing_rule_ids(args.owner, args.repo, headers)

    if args.dry_run:
        for g in target_groups:
            print(f"[dry-run] Would create: [{g['severity'].upper()}] {g['rule_id']} ({g['occurrence_count']} occurrence(s))")
        return

    for g in target_groups:
        if g["rule_id"] in existing_rule_ids:
            print(f"Skipped (already open): {g['rule_id']}")
            continue
        create_issue(args.owner, args.repo, headers, g)


if __name__ == "__main__":
    main()