import csv
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import build, submit


NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)
HASH = "sha256:" + "0" * 64


def vote_row(ip, reporter, vote="+1", count="10", last_seen="2026-09-02T00:00:00Z"):
    return [
        ip,
        reporter,
        vote,
        count,
        "2026-09-01T00:00:00Z",
        last_seen,
        "auth_login",
        "Go-http-client/2.0",
        HASH,
    ]


class BuildTests(unittest.TestCase):
    def make_repo(self, rows):
        root = Path(tempfile.mkdtemp())
        (root / "votes").mkdir()
        (root / "blocklist").mkdir()
        (root / "whitelist.txt").write_text("1.1.1.1/32\n10.0.0.0/8\n", encoding="utf-8")
        with (root / "votes" / "2026-09.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(build.HEADER)
            writer.writerows(rows)
        return root

    def test_aggregate_threshold_and_outputs(self):
        rows = [
            vote_row("93.184.216.34", "alice"),
            vote_row("93.184.216.34", "bob"),
            vote_row("93.184.216.35", "alice"),
            vote_row("93.184.216.36", "alice", vote="+1"),
            vote_row("93.184.216.36", "bob", vote="+1"),
        ]
        root = self.make_repo(rows)
        entries = build.build(root, NOW, 90, 30)
        self.assertEqual([entry.ip for entry in entries], ["93.184.216.34", "93.184.216.36"])
        payload = json.loads((root / "blocklist" / "ips.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["entries"][0]["reporter_count"], 2)
        self.assertEqual((root / "blocklist" / "ips.txt").read_text(), "93.184.216.34\n93.184.216.36\n")

    def test_rejects_duplicate_reporter_and_whitelist(self):
        root = self.make_repo([vote_row("93.184.216.34", "alice"), vote_row("93.184.216.34", "alice", "-1")])
        with self.assertRaisesRegex(ValueError, "only once"):
            build.build(root, NOW, 90, 30)
        root = self.make_repo([vote_row("1.1.1.1", "alice")])
        with self.assertRaisesRegex(ValueError, "whitelist"):
            build.build(root, NOW, 90, 30)

    def test_negative_votes_do_not_count_as_supporting_reporters(self):
        root = self.make_repo(
            [
                vote_row("93.184.216.34", "alice", "+1"),
                vote_row("93.184.216.34", "bob", "-1"),
            ]
        )
        self.assertEqual(build.build(root, NOW, 90, 30), [])

    def test_append_only_check_allows_append_and_rejects_reorder(self):
        root = self.make_repo([vote_row("93.184.216.34", "alice")])
        def git(*args):
            return subprocess.run(
                ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", *args],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        git("init", "-b", "main")
        git("add", ".")
        git("commit", "-m", "base")
        base = git("rev-parse", "HEAD")
        with (root / "votes" / "2026-09.csv").open("a", encoding="utf-8", newline="") as handle:
            csv.writer(handle, lineterminator="\n").writerow(vote_row("93.184.216.35", "bob"))
        git("add", ".")
        git("commit", "-m", "append")
        build.check_pr_append_only(f"{base}...HEAD", "bob", root)

        lines = (root / "votes" / "2026-09.csv").read_text(encoding="utf-8").splitlines()
        (root / "votes" / "2026-09.csv").write_text(
            "\n".join([lines[0], lines[2], lines[1]]) + "\n", encoding="utf-8"
        )
        git("add", ".")
        git("commit", "-m", "reorder")
        with self.assertRaisesRegex(ValueError, "edited or reordered"):
            build.check_pr_append_only(f"{base}...HEAD", "bob", root)


class SubmitTests(unittest.TestCase):
    def test_dry_run_does_not_write(self):
        root = BuildTests().make_repo([])
        result = submit.main(
            [
                "--repo-root",
                str(root),
                "--ip",
                "93.184.216.35",
                "--reporter",
                "alice",
                "--vote",
                "no",
                "--count",
                "3",
                "--ip-source",
                "direct",
                "--confirm-real-ip",
                "--month",
                "2026-09",
                "--dry-run",
            ]
        )
        self.assertEqual(result, 0)
        self.assertEqual(
            (root / "votes" / "2026-09.csv").read_text(encoding="utf-8"),
            ",".join(build.HEADER) + "\n",
        )

    def test_manual_submission_appends_normalized_row(self):
        root = BuildTests().make_repo([])
        result = submit.main(
            [
                "--repo-root",
                str(root),
                "--ip",
                "93.184.216.34",
                "--reporter",
                "alice",
                "--vote",
                "yes",
                "--count",
                "198",
                "--first-seen",
                "2026-09-02T01:12:00Z",
                "--last-seen",
                "2026-09-02T09:40:00Z",
                "--category",
                "auth_login",
                "--ua",
                "Go-http-client/2.0",
                "--ip-source",
                "nginx",
                "--confirm-real-ip",
                "--evidence-summary",
                "198 failed login responses; real client IP confirmed",
                "--month",
                "2026-09",
            ]
        )
        self.assertEqual(result, 0)
        with (root / "votes" / "2026-09.csv").open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]["vote"], "+1")
        self.assertEqual(rows[0]["count"], "198")
        self.assertTrue(rows[0]["evidence_hash"].startswith("sha256:"))
        self.assertEqual(
            submit.main(
                [
                    "--repo-root",
                    str(root),
                    "--ip",
                    "93.184.216.34",
                    "--reporter",
                    "alice",
                    "--vote",
                    "no",
                    "--count",
                    "1",
                    "--ip-source",
                    "nginx",
                    "--confirm-real-ip",
                ]
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
