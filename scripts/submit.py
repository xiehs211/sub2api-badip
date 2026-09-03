#!/usr/bin/env python3
"""Append one manually reviewed IP vote to the current vote file."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from scripts.build import (
        CATEGORY_RE,
        HEADER,
        MAX_COUNT,
        MONTH_FILE_RE,
        REPORTER_RE,
        UA_RE,
        format_time,
        load_whitelist,
        normalize_ip,
        parse_time,
        read_votes,
        rejection_reason,
    )
except ModuleNotFoundError:
    from build import (  # type: ignore[no-redef]
        CATEGORY_RE,
        HEADER,
        MAX_COUNT,
        MONTH_FILE_RE,
        REPORTER_RE,
        UA_RE,
        format_time,
        load_whitelist,
        normalize_ip,
        parse_time,
        read_votes,
        rejection_reason,
    )

UTC = timezone.utc
VOTE_ALIASES = {"yes": "+1", "no": "-1", "+1": "+1", "-1": "-1"}


def normalize_vote(value: str) -> str:
    try:
        return VOTE_ALIASES[value.strip().casefold()]
    except KeyError as exc:
        raise ValueError("vote must be yes/no or +1/-1") from exc


def evidence_hash(
    ip: str,
    reporter: str,
    vote: str,
    count: int,
    first_seen: datetime,
    last_seen: datetime,
    category: str,
    ua: str,
    ip_source: str,
    evidence_summary: str,
) -> str:
    summary = {
        "category": category,
        "count": count,
        "evidence_summary": evidence_summary,
        "first_seen": format_time(first_seen),
        "ip": ip,
        "ip_source": ip_source,
        "last_seen": format_time(last_seen),
        "reporter": reporter.casefold(),
        "ua": ua,
        "vote": vote,
    }
    digest = hashlib.sha256(
        json.dumps(summary, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def make_row(args: argparse.Namespace, whitelist: list, now: datetime) -> dict[str, str]:
    ip = normalize_ip(args.ip)
    if reason := rejection_reason(ip, whitelist):
        raise ValueError(f"{reason}: {ip}")

    reporter = args.reporter.strip()
    if not REPORTER_RE.fullmatch(reporter):
        raise ValueError(f"invalid GitHub reporter: {reporter!r}")

    vote = normalize_vote(args.vote)
    if args.count < 1 or args.count > MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")

    last_seen = parse_time(args.last_seen or format_time(now), "last_seen")
    first_seen = parse_time(args.first_seen or args.last_seen or format_time(now), "first_seen")
    if first_seen > last_seen:
        raise ValueError("first_seen is after last_seen")

    category = args.category.strip()
    if not CATEGORY_RE.fullmatch(category):
        raise ValueError(f"invalid category: {category!r}")
    ua = args.ua.strip()
    if not UA_RE.fullmatch(ua):
        raise ValueError("ua must be a short sanitized family, for example Go-http-client/2.0")
    evidence_summary = args.evidence_summary.strip()
    if len(evidence_summary) > 512:
        raise ValueError("evidence-summary must be at most 512 characters")

    return {
        "ip": ip,
        "reporter": reporter,
        "vote": vote,
        "count": str(args.count),
        "first_seen": format_time(first_seen),
        "last_seen": format_time(last_seen),
        "category": category,
        "ua": ua,
        "evidence_hash": evidence_hash(
            ip,
            reporter,
            vote,
            args.count,
            first_seen,
            last_seen,
            category,
            ua,
            args.ip_source,
            evidence_summary,
        ),
    }


def append_row(path: Path, row: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    if exists:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            if next(csv.reader([handle.readline().rstrip("\r\n")]), []) != HEADER:
                raise ValueError(f"{path}: header must be exactly {','.join(HEADER)}")
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADER, lineterminator="\n")
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True, help="public client IP manually confirmed from your logs")
    parser.add_argument("--reporter", required=True, help="your GitHub login")
    parser.add_argument("--vote", choices=["yes", "no", "+1", "-1"], required=True)
    parser.add_argument("--count", type=int, required=True, help="number of observed login attempts")
    parser.add_argument("--first-seen", help="ISO-8601 timestamp; defaults to last-seen")
    parser.add_argument("--last-seen", help="ISO-8601 timestamp; defaults to now")
    parser.add_argument("--category", default="auth_login")
    parser.add_argument("--ua", default="unknown", help="short sanitized UA family, not the full UA")
    parser.add_argument(
        "--ip-source",
        choices=["direct", "nginx", "cloudflare"],
        required=True,
        help="where you manually confirmed the real client IP",
    )
    parser.add_argument(
        "--confirm-real-ip",
        action="store_true",
        help="required acknowledgement that this is not a CDN/proxy node IP",
    )
    parser.add_argument("--evidence-summary", default="", help="optional local note; only its hash is uploaded")
    parser.add_argument("--month", help="vote file month, YYYY-MM; defaults to current UTC month")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dry-run", action="store_true", help="validate and print the row without writing it")
    args = parser.parse_args(argv)
    if not args.confirm_real_ip:
        parser.error("--confirm-real-ip is required; never submit an unverified proxy IP")

    now = datetime.now(UTC)
    month = args.month or now.strftime("%Y-%m")
    if not MONTH_FILE_RE.fullmatch(f"{month}.csv"):
        parser.error("--month must be YYYY-MM")

    repo_root = args.repo_root.resolve()
    try:
        whitelist = load_whitelist(repo_root / "whitelist.txt")
        row = make_row(args, whitelist, now)
        votes = read_votes(repo_root / "votes", whitelist, now)
        if any(vote.ip == row["ip"] and vote.reporter.casefold() == row["reporter"].casefold() for vote in votes):
            raise ValueError("this reporter has already voted for this IP")
        if not args.dry_run:
            append_row(repo_root / "votes" / f"{month}.csv", row)
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
        print("validated; no file written" if args.dry_run else f"appended to votes/{month}.csv", file=sys.stderr)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
