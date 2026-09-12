import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from privacy_gateway.cli import main
from privacy_gateway.lifecycle import graceful_termination


class HandlerLifetimeTests(unittest.TestCase):
    def test_normal_and_exceptional_exit_restore_handlers_without_touching_sigint(self):
        original = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
        for fail in (False, True):
            try:
                with graceful_termination() as state:
                    self.assertIs(signal.getsignal(signal.SIGINT), original[signal.SIGINT])
                    self.assertIsNot(signal.getsignal(signal.SIGTERM), original[signal.SIGTERM])
                    self.assertIsNone(state.exit_code)
                    if fail:
                        raise RuntimeError("synthetic failure")
            except RuntimeError:
                pass
            for sig, previous in original.items():
                self.assertIs(signal.getsignal(sig), previous)

    def test_worker_thread_does_not_change_global_signal_handlers(self):
        results = []
        before = signal.getsignal(signal.SIGTERM)
        def worker():
            with graceful_termination() as state:
                results.append((state.exit_code, signal.getsignal(signal.SIGTERM)))
        thread = threading.Thread(target=worker)
        thread.start(); thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, [(None, before)])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_normal_cli_result_and_sigint_semantics_are_preserved(self):
        with patch("privacy_gateway.terminal_entry.run", return_value=7):
            self.assertEqual(main([]), 7)
        with patch("privacy_gateway.terminal_entry.run", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            main([])


@unittest.skipUnless(hasattr(signal, "SIGHUP"), "Requires POSIX termination signals")
class OwnedProcessTerminationTests(unittest.TestCase):
    def test_term_and_hup_unwind_real_terminal_entry_cleanup_and_stop_owned_child(self):
        # Execute the real cli.main -> terminal_entry.run -> _terminal_session
        # cleanup chain, substituting only the model/UI/server resources. The
        # fake local runtime is a real child in its own process session, matching
        # the lifecycle property that caused the orphaned Ollama process.
        driver = r'''
import json,signal,subprocess,sys,time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from privacy_gateway.cli import main
root=Path(sys.argv[1])
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True,
                       stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
(root/'child.pid').write_text(str(child.pid))
closed=[]
def old_term(signum,frame):
    raise AssertionError('Previous handler must not run during MaskCode')
signal.signal(signal.SIGTERM,old_term)
signal.signal(signal.SIGHUP,old_term)
old_int=signal.getsignal(signal.SIGINT)
class State:
    def close(self):
        (root/'closing').write_text('cleanup entered')
        time.sleep(.3)
        child.terminate();child.wait(3)
        closed.append('state')
class Server:
    state=State()
    server_port=49999
    def shutdown(self):closed.append('shutdown')
    def server_close(self):closed.append('server_close')
class Engine:
    def __init__(self,*a,**k):pass
    def close(self):closed.append('engine')
class App:
    def __init__(self,*a,**k):pass
    def bind(self,*a):pass
    def post_event(self,*a):pass
    def run(self,**kwargs):
        print(json.dumps({'ready':True,'child':child.pid}),flush=True)
        while True:signal.pause()
try:
    with patch('privacy_gateway.cli.start_gateway',return_value=Server()), \
         patch('privacy_gateway.terminal_entry.self_test',return_value=True), \
         patch('privacy_gateway.terminal.TerminalApp',App), \
         patch('privacy_gateway.engine.ClaudeEngine',Engine), \
         patch.object(sys.stdin,'isatty',return_value=True), \
         patch.object(sys.stdout,'isatty',return_value=True):
        result=main(['--mask-cwd',str(root)])
    print(json.dumps({'result':result,'closed':closed,'child_stopped':child.poll() is not None,
        'handlers_restored':signal.getsignal(signal.SIGTERM) is old_term and signal.getsignal(signal.SIGHUP) is old_term,
        'sigint_unchanged':signal.getsignal(signal.SIGINT) is old_int}),flush=True)
    sys.exit(result)
finally:
    if child.poll() is None:child.kill();child.wait()
'''
        project = Path(__file__).resolve().parents[1]
        for sig in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory(prefix="maskcode-signal-test-") as temporary:
                root = Path(temporary)
                process = subprocess.Popen([sys.executable, "-c", driver, temporary], cwd=project,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    # A bounded select prevents hanging if startup fails before
                    # the fake UI reaches its wait loop.
                    import select
                    self.assertTrue(select.select([process.stdout], [], [], 8)[0], "Child never became ready")
                    ready_line = process.stdout.readline()
                    self.assertTrue(ready_line, "Child exited before terminal startup")
                    ready = json.loads(ready_line)
                    self.assertTrue(ready["ready"])
                    process.send_signal(sig)
                    deadline = time.monotonic() + 3
                    while not (root / "closing").exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue((root / "closing").exists(), "Terminal finally block did not run")
                    # A repeated signal must not interrupt child cleanup.
                    process.send_signal(sig)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(stderr, "")
                    report = json.loads(stdout.strip())
                    self.assertEqual(process.returncode, 128 + sig)
                    self.assertEqual(report["result"], 128 + sig)
                    self.assertEqual(report["closed"], ["state", "engine", "shutdown", "server_close"])
                    self.assertTrue(report["child_stopped"])
                    self.assertTrue(report["handlers_restored"])
                    self.assertTrue(report["sigint_unchanged"])
                    with self.assertRaises(ProcessLookupError):
                        os.kill(ready["child"], 0)
                finally:
                    if process.poll() is None:
                        process.kill(); process.wait()
                    # If the driver is killed by a failing test, clean only the
                    # synthetic child PID that this exact test created.
                    pid_file = root / "child.pid"
                    if pid_file.exists():
                        try:os.kill(int(pid_file.read_text()), signal.SIGKILL)
                        except ProcessLookupError:pass
                    if process.stdout:process.stdout.close()
                    if process.stderr:process.stderr.close()


if __name__ == "__main__":
    unittest.main()
