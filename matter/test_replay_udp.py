"""Transport-size failures are valid history, not malformed archive framing."""
import errno
import subprocess
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

import replay_worker as worker


def frame(*messages):
    return b"".join(len(msg).to_bytes(4, "little") + msg for msg in messages)


class ReplayUDPTest(unittest.TestCase):
    def test_waits_for_the_spawned_process_udp_socket(self):
        port = 49191
        child = subprocess.Popen([
            sys.executable, "-c",
            "import socket,time; time.sleep(.1); "
            f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',{port})); "
            "time.sleep(2)",
        ])
        try:
            elapsed = worker.wait_for_udp_ready(
                child, port, timeout_seconds=1, settle_seconds=0)
            self.assertGreaterEqual(elapsed, 0.05)
            self.assertLess(elapsed, 1)
        finally:
            child.terminate()
            child.wait(timeout=5)

    def test_readiness_rejects_a_port_owned_by_another_process(self):
        port = 49192
        owner = subprocess.Popen([
            sys.executable, "-c",
            "import socket,time; "
            f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',{port})); "
            "time.sleep(2)",
        ])
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
        try:
            time.sleep(0.1)
            with self.assertRaisesRegex(RuntimeError, "did not bind"):
                worker.wait_for_udp_ready(
                    unrelated, port, timeout_seconds=0.05, settle_seconds=0)
        finally:
            owner.terminate(); unrelated.terminate()
            owner.wait(timeout=5); unrelated.wait(timeout=5)

    def test_oversized_message_keeps_prefix_and_tail_in_parser(self):
        messages = [b"prefix", b"x" * 65508, b"tail"]
        self.assertEqual(worker.split_aflnet(frame(*messages)), messages)

    def test_invalid_framing_still_fails_closed(self):
        for data in (b"", b"\0" * 4, frame(b"a")[:-1], frame(b"a") + b"x",
                     (999999).to_bytes(4, "little") + b"x"):
            self.assertEqual(worker.split_aflnet(data), [])

    def run_send(self, messages, results):
        process = MagicMock()
        process.poll.return_value = None
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.send.side_effect = results
        with patch.object(worker.socket, "socket", return_value=sock), \
             patch.object(worker, "recv_burst", return_value=[]) as recv:
            rows = worker.send_requests(messages, process)
        return rows, sock, recv

    def test_send_failure_retains_prefix_and_does_not_send_tail(self):
        rows, sock, recv = self.run_send(
            [b"ok", b"x" * 65508, b"tail"], [2, OSError(errno.EMSGSIZE, "too long")])
        self.assertEqual(sock.send.call_count, 2)
        self.assertEqual([r["sent"] for r in rows], [True, False])
        self.assertEqual(rows[1]["transport_error"]["name"], "EMSGSIZE")
        self.assertEqual(recv.call_count, 2)  # prefix receive and final receive

    def test_first_message_oversized_still_gets_final_receive(self):
        rows, sock, recv = self.run_send(
            [b"x" * 65508, b"tail"], [OSError(errno.EMSGSIZE, "too long")])
        self.assertEqual(sock.send.call_count, 1)
        self.assertFalse(rows[0]["sent"])
        self.assertEqual(recv.call_count, 1)

    def test_other_transport_failures_are_not_swallowed(self):
        with self.assertRaises(OSError):
            self.run_send([b"ok"], [OSError(errno.ECONNREFUSED, "refused")])
        with self.assertRaises(OSError):
            self.run_send([b"ok"], [OSError(errno.EMSGSIZE, "unexpected")])

    def test_short_send_is_failure(self):
        with self.assertRaisesRegex(RuntimeError, "short UDP send"):
            self.run_send([b"ok"], [1])


if __name__ == "__main__":
    unittest.main()
