"""Disjoint fresh-process batches must never add an earlier raw twice."""
import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from replay_snapshots import publish_snapshots


class IncrementalSnapshotsTest(unittest.TestCase):
    def test_merge_uses_only_new_raw_and_previous_indexed_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raws = []
            for i in range(2):
                path = root / f"raw-{i}.profraw"
                path.write_text(str(i + 1))
                raws.append(dict(index=i, path=str(path), sha256=str(i), size=1))
            calls = []

            def merge(argv, **_kwargs):
                calls.append(argv)
                inputs = argv[2:argv.index("-o")]
                Path(argv[-1]).write_text(str(sum(int(Path(p).read_text()) for p in inputs)))
                class Result:
                    returncode, stdout, stderr = 0, "", ""
                return Result()

            with patch("replay_snapshots.subprocess.run", side_effect=merge):
                publish_snapshots(root, raws, [(0, [0]), (1800, [1]), (3600, [])],
                                  "llvm-profdata", {}, incremental=True)
            self.assertEqual((root / "snapshots/snapshot-0s.profdata").read_text(), "1")
            self.assertEqual((root / "snapshots/snapshot-1800s.profdata").read_text(), "3")
            self.assertEqual((root / "snapshots/snapshot-3600s.profdata").read_text(), "3")
            self.assertNotIn(raws[0]["path"], calls[1])
            self.assertIn(raws[1]["path"], calls[1])
            self.assertNotIn(raws[0]["path"], calls[2])
            self.assertNotIn(raws[1]["path"], calls[2])
            with (root / "raw-inputs/snapshot-3600s.tsv").open() as f:
                ledger = list(csv.DictReader(f, delimiter="\t"))
            self.assertEqual([row["seed_index"] for row in ledger], ["0", "1"])

    def test_overlapping_indices_fail_before_merge(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("replay_snapshots.subprocess.run") as merge:
                with self.assertRaisesRegex(RuntimeError, "exactly once"):
                    publish_snapshots(temporary, [{"path": "a"}], [(0, [0]), (1800, [0])],
                                      "llvm-profdata", {}, incremental=True)
                merge.assert_not_called()


if __name__ == "__main__":
    unittest.main()
