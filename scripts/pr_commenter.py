"""GitHub Pull Request Security Commenter CLI for RedCell.

Usage:
    # Print formatted comment to terminal
    python scripts/pr_commenter.py

    # Output to markdown file
    python scripts/pr_commenter.py --output pr_comment.md

    # Append to GitHub Actions Job Summary ($GITHUB_STEP_SUMMARY)
    python scripts/pr_commenter.py --write-step-summary

    # Post directly to GitHub PR
    python scripts/pr_commenter.py --post --repo owner/repo --pr 42 --token $GITHUB_TOKEN
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Configure UTF-8 stdout
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redcell.reporting.pr_comment import generate_pr_comment, post_pr_comment


def find_report_file(specified_path: str | None = None) -> str | None:
    if specified_path and os.path.exists(specified_path):
        return specified_path

    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "reports", "report.json"),
        os.path.join(os.path.dirname(__file__), "..", "reports", "report-hardened.json"),
        os.path.join(os.path.dirname(__file__), "..", "web", "last-live", "report.json"),
        os.path.join(os.path.dirname(__file__), "..", "web", "last-live", "report-hardened.json"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def find_patch_text(specified_path: str | None = None) -> str | None:
    if specified_path and os.path.exists(specified_path):
        try:
            with open(specified_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return None

    patch_candidate = os.path.join(os.path.dirname(__file__), "..", "reports", "patches", "redcell-hardening.patch")
    if os.path.exists(patch_candidate):
        try:
            with open(patch_candidate, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    return None


def get_pr_number_from_event() -> int | None:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and os.path.exists(event_path):
        try:
            with open(event_path, "r", encoding="utf-8") as f:
                event = json.load(f)
            # Pull Request event
            if "pull_request" in event and "number" in event["pull_request"]:
                return int(event["pull_request"]["number"])
            # Issue comment event
            if "issue" in event and "number" in event["issue"] and "pull_request" in event["issue"]:
                return int(event["issue"]["number"])
        except Exception:
            pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="RedCell GitHub PR Security Commenter")
    ap.add_argument("--report", type=str, default=None, help="Path to report JSON")
    ap.add_argument("--patch", type=str, default=None, help="Path to patch file")
    ap.add_argument("--output", type=str, default=None, help="Path to write output markdown")
    ap.add_argument("--write-step-summary", action="store_true", help="Append markdown to GITHUB_STEP_SUMMARY")
    ap.add_argument("--post", action="store_true", help="Post comment to GitHub PR via API")
    ap.add_argument("--repo", type=str, default=None, help="GitHub repository (owner/repo)")
    ap.add_argument("--pr", type=int, default=None, help="GitHub Pull Request number")
    ap.add_argument("--token", type=str, default=None, help="GitHub Token")
    args = ap.parse_args()

    report_path = find_report_file(args.report)
    if not report_path:
        print("Error: Could not locate a RedCell report.json file.", file=sys.stderr)
        return 1

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    except Exception as e:
        print(f"Error reading report JSON ({report_path}): {e}", file=sys.stderr)
        return 1

    patch_text = find_patch_text(args.patch)
    comment_md = generate_pr_comment(report_data, patch_text=patch_text)

    # 1. Output file if specified
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(comment_md)
            print(f"PR Comment written to: {args.output}")
        except Exception as e:
            print(f"Error writing to output file: {e}", file=sys.stderr)
            return 1

    # 2. Append to GitHub Step Summary if requested or if GITHUB_STEP_SUMMARY is present
    if args.write_step_summary or (os.environ.get("GITHUB_STEP_SUMMARY") and not args.post):
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            try:
                with open(summary_file, "a", encoding="utf-8") as f:
                    f.write(comment_md + "\n\n")
                print(f"Appended comment to GITHUB_STEP_SUMMARY: {summary_file}")
            except Exception as e:
                print(f"Warning: Failed to write to GITHUB_STEP_SUMMARY: {e}", file=sys.stderr)

    # 3. Post to GitHub PR if requested
    if args.post:
        repo = args.repo or os.environ.get("GITHUB_REPOSITORY")
        pr_num = args.pr or get_pr_number_from_event()
        token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

        if not repo or not pr_num or not token:
            print("Error: --post requires --repo, --pr, and --token (or corresponding env vars).", file=sys.stderr)
            return 1

        try:
            res = post_pr_comment(comment_md, repo, pr_num, token)
            print(f"Successfully posted comment to {repo} PR #{pr_num}! (ID: {res.get('id')})")
        except Exception as e:
            print(f"Error posting comment to GitHub: {e}", file=sys.stderr)
            return 1

    # If neither output nor post, print markdown to stdout
    if not args.output and not args.post:
        print(comment_md)

    return 0


if __name__ == "__main__":
    sys.exit(main())
