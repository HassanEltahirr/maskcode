"""One macOS Seatbelt boundary for the Codex client and its child tools.

Reads remain available. Writes are restricted to explicitly selected workspaces,
private launch scratch, the official Codex state directory, and terminal devices.
Direct network sockets can reach only MaskCode's loopback gateway. This retains
filesystem restrictions while avoiding macOS's unsupported nested Seatbelt call.
Like the existing launcher, it is not an OS-helper/IPC security boundary.
"""
import json
from pathlib import Path
import platform


def _directory(value, *, must_exist=True):
    try:
        path = Path(value).expanduser().resolve(strict=must_exist)
        if path == Path("/") or (path.exists() and not path.is_dir()):
            raise ValueError()
        return path
    except (OSError, ValueError, TypeError):
        raise ValueError("A Codex writable directory is invalid or too broad") from None


def profile(port, workspaces, temporary, state):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid gateway port")
    roots = [_directory(path) for path in workspaces]
    if not roots:
        raise ValueError("Codex requires a workspace directory")
    roots += [_directory(temporary), _directory(state, must_exist=False)]
    roots = list(dict.fromkeys(roots))
    scope = "\n".join("  (subpath " + json.dumps(str(path), ensure_ascii=False) + ")" for path in roots)
    return ('(version 1)\n(allow default)\n(deny network*)\n'
            '(allow network-outbound (remote tcp "localhost:%d"))\n'
            '(deny file-write*)\n(allow file-write*\n%s\n'
            '  (literal "/dev/null")\n'
            '  (regex #"^/dev/(tty|ttys[0-9]+|ptmx)$"))\n' % (port, scope))


def command(port, argv, workspaces, temporary, state):
    if not argv or any(not isinstance(value, str) or "\0" in value for value in argv):
        raise ValueError("Invalid protected Codex command")
    if platform.system() != "Darwin" or not Path("/usr/bin/sandbox-exec").exists():
        raise RuntimeError("The protected Codex launcher requires macOS sandbox-exec")
    return ["/usr/bin/sandbox-exec", "-p", profile(port, workspaces, temporary, state), *argv]
