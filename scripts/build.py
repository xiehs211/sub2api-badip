#!/usr/bin/env python3
"""Validate votes and build the derived blocklist files."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

HEADER = [
    "ip",
    "reporter",
    "vote",
    "count",
    "first_seen",
    "last_seen",
    "category",
    "ua",
    "evidence_hash",
]
REPORTER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")
UA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,63}$")
EVIDENCE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MONTH_FILE_RE = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])\.csv$")
INTEGER_RE = re.compile(r"^[1-9][0-9]*$")
MAX_COUNT = 1_000_000
DEFAULT_TTL_DAYS = 90
SCAN_TTL_DAYS = 30
UTC = timezone.utc


@dataclass(frozen=True)
class Vote:
    ip: str
    reporter: str
    vote: int
    count: int
    first_seen: datetime
    last_seen: datetime
    category: str
    ua: str
    evidence_hash: str


@dataclass
class Entry:
    ip: str
    net_votes: int = 0
    attempts: int = 0
    reporters: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    categories: set[str] = field(default_factory=set)
    ua: set[str] = field(default_factory=set)

    def add(self, vote: Vote) -> None:
        self.net_votes += vote.vote
        self.attempts += vote.count
        if vote.vote > 0:
            self.reporters.add(vote.reporter)
        self.first_seen = min(self.first_seen or vote.first_seen, vote.first_seen)
        self.last_seen = max(self.last_seen or vote.last_seen, vote.last_seen)
        self.categories.add(vote.category)
        self.ua.add(vote.ua)


def parse_time(value: str, field_name: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(UTC)


def format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_now(value: str | None) -> datetime:
    return parse_time(value, "now") if value else datetime.now(UTC)


def load_whitelist(path: Path) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    if not path.exists():
        raise ValueError(f"whitelist not found: {path}")
    for line_number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid whitelist entry at {path}:{line_number}: {value!r}") from exc
    return networks


def normalize_ip(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc
    return str(parsed)


def rejection_reason(ip: str, whitelist: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> str | None:
    parsed = ipaddress.ip_address(ip)
    if not parsed.is_global:
        return "IP is not globally routable"
    if any(parsed in network for network in whitelist):
        return "IP is in whitelist"
    return None


def validate_row(
    row: dict[str, str | None],
    source: Path,
    line_number: int,
    whitelist: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
    now: datetime,
) -> Vote:
    if set(row) != set(HEADER):
        raise ValueError(f"{source}:{line_number}: columns must be exactly {','.join(HEADER)}")
    values = {key: (row[key] or "").strip() for key in HEADER}
    ip = normalize_ip(values["ip"])
    if reason := rejection_reason(ip, whitelist):
        raise ValueError(f"{source}:{line_number}: {reason}: {ip}")

    reporter = values["reporter"]
    if not REPORTER_RE.fullmatch(reporter):
        raise ValueError(f"{source}:{line_number}: invalid GitHub reporter: {reporter!r}")

    if values["vote"] not in {"+1", "-1"}:
        raise ValueError(f"{source}:{line_number}: vote must be +1 or -1")
    if not INTEGER_RE.fullmatch(values["count"]):
        raise ValueError(f"{source}:{line_number}: count must be a positive integer")
    count = int(values["count"])
    if count > MAX_COUNT:
        raise ValueError(f"{source}:{line_number}: count exceeds {MAX_COUNT}")

    first_seen = parse_time(values["first_seen"], f"{source}:{line_number}: first_seen")
    last_seen = parse_time(values["last_seen"], f"{source}:{line_number}: last_seen")
    if first_seen > last_seen:
        raise ValueError(f"{source}:{line_number}: first_seen is after last_seen")
    if last_seen > now + timedelta(days=1):
        raise ValueError(f"{source}:{line_number}: last_seen is too far in the future")

    category = values["category"]
    if not CATEGORY_RE.fullmatch(category):
        raise ValueError(f"{source}:{line_number}: invalid category: {category!r}")
    ua = values["ua"]
    if not UA_RE.fullmatch(ua):
        raise ValueError(f"{source}:{line_number}: ua must be a short sanitized family")
    evidence_hash = values["evidence_hash"]
    if not EVIDENCE_RE.fullmatch(evidence_hash):
        raise ValueError(f"{source}:{line_number}: evidence_hash must be sha256:<64 lowercase hex>")

    return Vote(
        ip=ip,
        reporter=reporter,
        vote=1 if values["vote"] == "+1" else -1,
        count=count,
        first_seen=first_seen,
        last_seen=last_seen,
        category=category,
        ua=ua,
        evidence_hash=evidence_hash,
    )


def read_votes(
    votes_dir: Path,
    whitelist: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
    now: datetime,
) -> list[Vote]:
    votes = []
    seen_pairs: dict[tuple[str, str], Path] = {}
    files = sorted(votes_dir.glob("*.csv"))
    for source in files:
        if not MONTH_FILE_RE.fullmatch(source.name):
            raise ValueError(f"vote file must be YYYY-MM.csv: {source}")
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != HEADER:
                raise ValueError(f"{source}: header must be exactly {','.join(HEADER)}")
            for line_number, row in enumerate(reader, 2):
                if None in row:
                    raise ValueError(f"{source}:{line_number}: too many CSV fields")
                vote = validate_row(row, source, line_number, whitelist, now)
                pair = (vote.ip, vote.reporter.casefold())
                if pair in seen_pairs:
                    raise ValueError(
                        f"{source}:{line_number}: reporter may vote for an IP only once; "
                        f"already seen in {seen_pairs[pair]}"
                    )
                seen_pairs[pair] = source
                votes.append(vote)
    return votes


def is_expired(vote: Vote, now: datetime, ttl_days: int, scan_ttl_days: int) -> bool:
    ttl = scan_ttl_days if vote.category == "scan" or vote.category.startswith("scan_") else ttl_days
    return vote.last_seen < now - timedelta(days=ttl)


def aggregate(
    votes: Iterable[Vote],
    now: datetime,
    ttl_days: int = DEFAULT_TTL_DAYS,
    scan_ttl_days: int = SCAN_TTL_DAYS,
) -> list[Entry]:
    entries: dict[str, Entry] = {}
    for vote in votes:
        if is_expired(vote, now, ttl_days, scan_ttl_days):
            continue
        entries.setdefault(vote.ip, Entry(vote.ip)).add(vote)
    return sorted(
        (
            entry
            for entry in entries.values()
            if len(entry.reporters) >= 2 or entry.net_votes >= 3
        ),
        key=lambda entry: ipaddress.ip_address(entry.ip),
    )


def entry_json(entry: Entry) -> dict[str, object]:
    assert entry.first_seen is not None and entry.last_seen is not None
    return {
        "ip": entry.ip,
        "net_votes": entry.net_votes,
        "reporters": sorted(entry.reporters, key=str.casefold),
        "reporter_count": len(entry.reporters),
        "attempts": entry.attempts,
        "first_seen": format_time(entry.first_seen),
        "last_seen": format_time(entry.last_seen),
        "categories": sorted(entry.categories),
        "ua": sorted(entry.ua),
    }


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=path.parent, delete=False
    )
    try:
        with temporary:
            temporary.write(content)
        os.replace(temporary.name, path)
    except Exception:
        try:
            os.unlink(temporary.name)
        except FileNotFoundError:
            pass
        raise


def write_outputs(repo_root: Path, entries: list[Entry], ttl_days: int, scan_ttl_days: int) -> None:
    blocklist = repo_root / "blocklist"
    ips = "".join(f"{entry.ip}\n" for entry in entries)
    nginx = "# generated by scripts/build.py; do not edit\n" + "".join(
        f"deny {entry.ip};\n" for entry in entries
    )
    payload = {
        "schema_version": 1,
        "rules": {
            "min_reporters": 2,
            "min_net_votes": 3,
            "ttl_days": ttl_days,
            "scan_ttl_days": scan_ttl_days,
        },
        "entries": [entry_json(entry) for entry in entries],
    }
    atomic_write(blocklist / "ips.txt", ips)
    atomic_write(blocklist / "nginx-deny.conf", nginx)
    atomic_write(
        blocklist / "ips.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
    )


def added_vote_lines(diff: str) -> list[dict[str, str]]:
    added = []
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        values = next(csv.reader([line[1:]]), [])
        if values == HEADER:
            continue
        if len(values) != len(HEADER):
            raise ValueError("added vote line is not a valid CSV row")
        added.append(dict(zip(HEADER, values)))
    return added


def check_pr_append_only(diff_base: str, reporter: str, repo_root: Path) -> None:
    base_ref = diff_base.split("...", 1)[0].strip()
    if not base_ref:
        raise ValueError("diff base must contain a Git ref")
    try:
        result = subprocess.run(
            ["git", "diff", "--unified=0", "--no-color", diff_base, "--", "votes"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"cannot inspect vote diff from {diff_base!r}") from exc
    diff = result.stdout
    try:
        changed = subprocess.run(
            ["git", "diff", "--name-only", diff_base, "--", "votes"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"cannot inspect changed vote files from {diff_base!r}") from exc
    for name in changed:
        path = Path(name)
        current_path = repo_root / path
        if not current_path.exists():
            raise ValueError("votes are append-only; existing vote files cannot be deleted")
        current = current_path.read_bytes()
        try:
            base = subprocess.run(
                ["git", "show", f"{base_ref}:{name}"],
                cwd=repo_root,
                check=True,
                capture_output=True,
            ).stdout
        except subprocess.CalledProcessError:
            base = None
        if base is not None and not current.startswith(base):
            raise ValueError("votes are append-only; existing vote rows cannot be edited or reordered")
    for row in added_vote_lines(diff):
        value = (row.get("reporter") or "").casefold()
        if value != reporter.casefold():
            raise ValueError(
                f"reporter {row.get('reporter')!r} does not match the PR author {reporter!r}"
            )


def build(repo_root: Path, now: datetime, ttl_days: int, scan_ttl_days: int) -> list[Entry]:
    whitelist = load_whitelist(repo_root / "whitelist.txt")
    votes = read_votes(repo_root / "votes", whitelist, now)
    entries = aggregate(votes, now, ttl_days, scan_ttl_days)
    write_outputs(repo_root, entries, ttl_days, scan_ttl_days)
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--now", help="override UTC time for deterministic checks")
    parser.add_argument("--ttl-days", type=int, default=DEFAULT_TTL_DAYS)
    parser.add_argument("--scan-ttl-days", type=int, default=SCAN_TTL_DAYS)
    parser.add_argument("--check-reporter", help="check added vote rows against a PR author")
    parser.add_argument("--diff-base", help="git diff base used with --check-reporter")
    args = parser.parse_args(argv)
    if args.ttl_days < 1 or args.scan_ttl_days < 1:
        parser.error("TTL values must be positive")
    if bool(args.check_reporter) != bool(args.diff_base):
        parser.error("--check-reporter and --diff-base must be used together")
    try:
        if args.check_reporter:
            check_pr_append_only(args.diff_base, args.check_reporter, args.repo_root.resolve())
        entries = build(args.repo_root.resolve(), parse_now(args.now), args.ttl_days, args.scan_ttl_days)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"built {len(entries)} active blocklist entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
