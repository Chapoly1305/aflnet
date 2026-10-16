"""Exercise the launcher's actual retention functions without Slurm/Apptainer."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


LAUNCHER = Path(__file__).with_name("run_campaign.sbatch")
SOURCE = LAUNCHER.read_text()
FUNCTIONS = SOURCE.split("# RETENTION_FUNCTIONS_BEGIN\n", 1)[1].split(
    "# RETENTION_FUNCTIONS_END", 1
)[0]


class CampaignRetentionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.campaign = self.root / "scratch" / "campaign"
        (self.campaign / "manifest").mkdir(parents=True)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        (self.runtime / "image.sif").write_bytes(b"temporary image")
        for i in range(1, 11):
            worker = self.campaign / f"instance-{i:02d}"
            for queue in ("queue", "replayable-queue"):
                directory = worker / "afl-out" / queue
                directory.mkdir(parents=True)
                (directory / "id:000000,orig:seed").write_bytes(b"input")
            (worker / "run.env").write_text(
                "status=ok\nrequested_fuzz_seconds=86400\n"
                "observed_fuzz_seconds=86400\nqueue_entries=1\n"
            )
            (worker / "instance.log").write_text("fuzzing complete\n")
            (worker / "afl-out" / "fuzzer_stats").write_text("execs_done : 100\n")
            (worker / ".done").touch()
        self.script = self.root / "test.sh"

    def launch(self, action):
        self.script.write_text(
            "#!/bin/bash\nset -euo pipefail\n" + FUNCTIONS + "\n"
            "FUZZ_SECONDS=86400\nREPLICAS=10\nPUBLISHED_OK=0\nSTEP_PID=''\n"
            "trap 'campaign_exit \"$?\"' EXIT\n"
            "trap 'exit 130' INT\ntrap 'exit 143' TERM USR1\n" + action
        )
        env = dict(os.environ, CAMPAIGN=str(self.campaign), local_root=str(self.runtime))
        return subprocess.Popen(
            ["bash", str(self.script)], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def run_action(self, action):
        process = self.launch(action)
        stdout, stderr = process.communicate(timeout=15)
        return process.returncode, stdout, stderr

    def assert_retained(self):
        for i in range(1, 11):
            for queue in ("queue", "replayable-queue"):
                self.assertEqual(
                    (self.campaign / f"instance-{i:02d}" / "afl-out" / queue /
                     "id:000000,orig:seed").read_bytes(), b"input"
                )
        self.assertFalse(self.runtime.exists())

    def test_ten_verified_replicas_complete_without_moving_inputs(self):
        original = self.campaign / "instance-01/afl-out/replayable-queue/id:000000,orig:seed"
        before = original.stat()
        rc, _, err = self.run_action("finish_campaign 0\n")
        self.assertEqual(rc, 0, err)
        self.assertTrue((self.campaign / "campaign.done").exists())
        self.assertEqual(original.stat().st_ino, before.st_ino)
        self.assertEqual(original.stat().st_mtime_ns, before.st_mtime_ns)
        self.assert_retained()

    def test_done_markers_cannot_hide_missing_replay_inputs(self):
        (self.campaign / "instance-10/afl-out/replayable-queue/id:000000,orig:seed").unlink()
        rc, _, _ = self.run_action("finish_campaign 0\n")
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.campaign / "campaign.done").exists())
        self.assertTrue((self.campaign / "campaign.failed").exists())
        manifest = (self.campaign / "manifest/campaign.env").read_text()
        self.assertIn("complete_instances=10\npublished_instances=9", manifest)
        self.assertTrue((self.campaign / "instance-01/afl-out/replayable-queue").is_dir())

    def test_nonzero_step_exit_is_failure_even_with_ten_done_markers(self):
        rc, _, _ = self.run_action("finish_campaign 143\n")
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.campaign / "campaign.done").exists())
        self.assert_retained()

    def test_incomplete_active_budget_cannot_complete(self):
        receipt = self.campaign / "instance-10/run.env"
        receipt.write_text(receipt.read_text().replace("observed_fuzz_seconds=86400", "observed_fuzz_seconds=3600"))
        rc, _, _ = self.run_action("finish_campaign 0\n")
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.campaign / "campaign.done").exists())
        self.assert_retained()

    def test_full_input_checksums_detect_payload_corruption(self):
        rc, _, err = self.run_action(
            'seal_instance "$CAMPAIGN/instance-01"\n'
            'printf corrupt > "$CAMPAIGN/instance-01/afl-out/replayable-queue/id:000000,orig:seed"\n'
            'if verify_publication "$CAMPAIGN/instance-01"; then exit 99; fi\n'
            'PUBLISHED_OK=1\n'
        )
        self.assertEqual(rc, 0, err)

    def test_cancellation_and_time_limit_signal_preserve_scratch(self):
        for sig in (signal.SIGTERM, signal.SIGUSR1, signal.SIGINT):
            with self.subTest(signal=sig):
                self.runtime.mkdir(exist_ok=True)
                ready = self.root / "ready"
                ready.unlink(missing_ok=True)
                process = self.launch(
                    'sleep 30 &\nSTEP_PID=$!\ntouch "${CAMPAIGN}/../../ready"\nwait "$STEP_PID"\n'
                )
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(ready.exists(), "signal test did not start")
                    process.send_signal(sig)
                    _, err = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 130 if sig == signal.SIGINT else 143, err)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                self.assertFalse((self.campaign / "campaign.done").exists())
                self.assertTrue((self.campaign / "campaign.failed").exists())
                self.assert_retained()

    def test_worker_binds_output_to_supplied_scratch_root(self):
        mock = self.root / "apptainer"
        mock.write_text('#!/bin/bash\nprintf "%s\\n" "$@" > "$ARGUMENTS"\n')
        mock.chmod(0o755)
        arguments = self.root / "arguments"
        env = dict(os.environ, AF_APPTAINER=str(mock), ARGUMENTS=str(arguments))
        result = subprocess.run(
            ["bash", str(LAUNCHER), "--instance", "11", "/rootfs", str(self.campaign), str(self.runtime)],
            env=env, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"{self.campaign}/instance-11:/workdir/output", arguments.read_text())
        self.assertIn(f"{self.runtime}/instance-11:/tmp", arguments.read_text())

    def test_cleanup_refuses_runtime_tree_containing_campaign(self):
        self.runtime = self.campaign.parent
        rc, _, _ = self.run_action("exit 143\n")
        self.assertEqual(rc, 143)
        self.assertTrue(self.runtime.exists())
        self.assertEqual(
            (self.campaign / "instance-01/afl-out/replayable-queue/id:000000,orig:seed").read_bytes(),
            b"input",
        )


if __name__ == "__main__":
    unittest.main()
