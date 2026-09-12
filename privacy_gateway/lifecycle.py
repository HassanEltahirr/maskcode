"""Route catchable process termination through MaskCode's owned-resource cleanup.

SIGTERM and SIGHUP unwind ordinary Python finally blocks. SIGINT keeps the
caller's/asyncio's existing behavior. SIGKILL, interpreter crashes and machine
shutdown cannot be made cleanup-safe by a Python signal handler.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import signal
import threading


class TerminationRequested(KeyboardInterrupt):
    """A catchable termination request, compatible with existing cleanup paths."""

    def __init__(self, signum):
        super().__init__()
        self.signum = signum


@dataclass
class TerminationState:
    signum: int | None = None

    @property
    def exit_code(self):
        return None if self.signum is None else 128 + self.signum


@contextmanager
def graceful_termination():
    """Temporarily handle TERM/HUP only when called from the main thread.

    Further termination signals during the first request's cleanup are ignored,
    so they cannot interrupt the finally blocks that stop owned child processes.
    Previous handlers are restored on every normal/exceptional exit.
    """
    state = TerminationState()
    if threading.current_thread() is not threading.main_thread():
        yield state
        return
    previous = {}
    exiting = False

    def terminate(signum, frame):
        if state.signum is not None:
            return
        state.signum = signum
        if not exiting:
            raise TerminationRequested(signum)

    try:
        for name in ("SIGTERM", "SIGHUP"):
            signum = getattr(signal, name, None)
            if signum is not None:
                previous[signum] = signal.getsignal(signum)
                signal.signal(signum, terminate)
        yield state
    finally:
        exiting = True
        for signum, handler in previous.items():
            signal.signal(signum, handler)
