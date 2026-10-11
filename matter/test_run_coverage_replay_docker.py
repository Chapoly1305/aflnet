"""Contract tests for the private-network coverage-replay launcher."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("run_coverage_replay_docker.sh")


class CoverageReplayDockerLauncherTest(unittest.TestCase):
    def fixture(self, root):
        analysis = root / "coverage-analysis"
        protected = root / "protected-runs"
        analysis.mkdir()
        protected.mkdir()
        (analysis / "run_source_coverage.py").touch()
        return analysis, protected

    def run_dry(self, analysis, protected, *extra):
        result = subprocess.run([
            str(SCRIPT), "--dry-run",
            "--image", "matter-coverage:test",
            "--name", "coverage-full-01",
            "--analysis-dir", str(analysis),
            "--protected-runs-dir", str(protected),
            "--cpuset", "4-7",
            *extra,
            "--", "--stage", "run", "--workers", "4",
            "--only", "full/instance-01",
        ], check=True, capture_output=True, text=True)
        return shlex.split(result.stdout)

    def test_private_bridge_is_mandatory(self):
        with tempfile.TemporaryDirectory() as temporary:
            analysis, protected = self.fixture(Path(temporary))
            argv = self.run_dry(analysis, protected)
        self.assertEqual(argv[argv.index("--network") + 1], "bridge")
        self.assertNotIn("host", argv)
        self.assertEqual(
            argv[argv.index("--label") + 1],
            "eclipsefuzz.coverage-replay-network=private-bridge",
        )
        self.assertEqual(argv[argv.index("--cpuset-cpus") + 1], "4-7")
        self.assertIn(f"{analysis}:{analysis}", argv)
        self.assertIn(f"{protected}:{protected}:ro", argv)

    def test_settle_and_replay_arguments_are_forwarded(self):
        with tempfile.TemporaryDirectory() as temporary:
            analysis, protected = self.fixture(Path(temporary))
            argv = self.run_dry(
                analysis, protected, "--startup-settle-seconds", "10")
        self.assertIn("AFLNET_REPLAY_STARTUP_SETTLE_SECONDS=10", argv)
        self.assertEqual(argv[-6:], [
            "--stage", "run", "--workers", "4", "--only", "full/instance-01",
        ])

    def test_host_network_cannot_be_requested(self):
        with tempfile.TemporaryDirectory() as temporary:
            analysis, protected = self.fixture(Path(temporary))
            result = subprocess.run([
                str(SCRIPT), "--dry-run",
                "--image", "matter-coverage:test",
                "--name", "coverage-full-01",
                "--analysis-dir", str(analysis),
                "--protected-runs-dir", str(protected),
                "--cpuset", "0-3",
                "--network", "host", "--", "--stage", "run",
            ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown launcher argument: --network", result.stderr)


if __name__ == "__main__":
    unittest.main()
