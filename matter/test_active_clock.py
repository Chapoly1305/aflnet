"""Fail-closed post-calibration time-zero evidence for Hopper queue replay."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from phase2_parallel import active_clock_for
from replay_snapshots import snapshot_plan


class ActiveClockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.instance = Path(self.temp.name)
        self.afl_out = self.instance / "afl-out"
        self.afl_out.mkdir()
        (self.instance / "run.env").write_text(
            "status=ok\n"
            "fuzz_start_epoch=100000\n"
            "fuzz_end_epoch=186400\n"
            "requested_fuzz_seconds=86400\n"
            "observed_fuzz_seconds=86400\n"
            "initial_calibration_seconds=100\n"
            "initial_calibration_status=ok\n"
            "initial_calibration_failures=0\n",
            encoding="utf-8",
        )
        (self.afl_out / "fuzzer_stats").write_text(
            "start_time : 99900\n"
            "active_fuzz_start_time : 100000\n"
            "active_fuzz_seconds : 86400\n"
            "last_update : 186400\n",
            encoding="utf-8",
        )

    def test_full_active_clock_excludes_calibration_and_has_48_windows(self) -> None:
        self.assertEqual(active_clock_for(str(self.instance), str(self.afl_out)), (100000, 86400))
        plan = snapshot_plan([0, 1800, 86400], 86400, 1800, 220)
        self.assertEqual(len(plan), 48)
        self.assertEqual(plan[-1][0], 86400)

    def test_missing_clock_fails_instead_of_falling_back_to_queue_mtime(self) -> None:
        (self.afl_out / "fuzzer_stats").unlink()
        with self.assertRaisesRegex(RuntimeError, "active-time run.env or fuzzer_stats missing"):
            active_clock_for(str(self.instance), str(self.afl_out))

    def test_conflicting_active_start_fails(self) -> None:
        stats = self.afl_out / "fuzzer_stats"
        stats.write_text(stats.read_text(encoding="utf-8").replace(
            "active_fuzz_start_time : 100000", "active_fuzz_start_time : 100001"
        ), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "inconsistent active-time"):
            active_clock_for(str(self.instance), str(self.afl_out))

    def test_partial_calibration_fails(self) -> None:
        run = self.instance / "run.env"
        run.write_text(run.read_text(encoding="utf-8").replace(
            "initial_calibration_failures=0", "initial_calibration_failures=1"
        ), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "initial corpus calibration"):
            active_clock_for(str(self.instance), str(self.afl_out))


if __name__ == "__main__":
    unittest.main()
