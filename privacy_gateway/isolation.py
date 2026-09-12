"""macOS direct socket restriction for the launched process and descendants.

This is a best-effort local prototype built on deprecated sandbox-exec. It does
not isolate filesystem data or defend against IPC delegation to an OS helper.
"""
from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path


def isolated_environment(environ=None):
    """Remove inherited loader and shell startup injection for child processes.

    This is defense in depth for the launcher, not a boundary against a hostile
    parent process, executable, PATH, shell configuration, or the local user.
    Ordinary project variables and terminal settings remain available.
    """
    env = dict(os.environ if environ is None else environ)
    exact = {"NODE_OPTIONS", "NODE_PATH", "NODE_CHANNEL_FD", "NODE_CHANNEL_SERIALIZATION_MODE",
             "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS", "NODE_USE_ENV_PROXY",
             "BASH_ENV", "ENV", "ZDOTDIR", "SHELLOPTS", "BASHOPTS", "FPATH",
             "PYTHONSTARTUP", "PYTHONINSPECT", "PERL5OPT", "RUBYOPT", "RUBYLIB"}
    for name in list(env):
        if (name in exact or name.startswith(("DYLD_", "LD_", "BUN_", "BASH_FUNC_"))
                or name.lower() in {"http_proxy", "https_proxy", "all_proxy", "ftp_proxy"}):
            del env[name]
    return env


def profile(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid gateway port")
    return ('(version 1)\n(allow default)\n(deny network*)\n'
            '(allow network-outbound (remote tcp "localhost:%d"))\n' % port)


def command(port, argv):
    if not argv or any(not isinstance(value, str) or "\0" in value for value in argv):
        raise ValueError("Invalid protected child command")
    if platform.system() != "Darwin" or not Path("/usr/bin/sandbox-exec").exists():
        raise RuntimeError("The client launcher currently requires macOS sandbox-exec; use serve only with your own network isolation")
    return ["/usr/bin/sandbox-exec", "-p", profile(port), *argv]


def self_test(port):
    """Verify allowed gateway and denied other-loopback/public sockets locally.

    A denied connect returns EPERM without a packet. If enforcement is broken,
    the public probe only opens a TCP connection; it carries no application data.
    """
    with socket.socket() as other:
        other.bind(("127.0.0.1", 0))
        other.listen(1)
        probe = '''import errno,json,socket,sys
def check(host,port):
    s=socket.socket(); s.settimeout(2)
    try:
        s.connect((host,port)); return "allowed"
    except OSError as e:
        return "blocked" if e.errno in (errno.EPERM,errno.EACCES) else "inconclusive"
    finally: s.close()
print(json.dumps([check("127.0.0.1",int(sys.argv[1])),check("127.0.0.1",int(sys.argv[2])),check("1.1.1.1",443)]))
'''
        result = subprocess.run(command(port, [sys.executable, "-I", "-S", "-c", probe,
                                              str(port), str(other.getsockname()[1])]),
                                capture_output=True, text=True, timeout=12,
                                env=isolated_environment(), close_fds=True)
    try:
        findings = json.loads(result.stdout)
    except ValueError:
        findings = []
    if result.returncode or findings != ["allowed", "blocked", "blocked"]:
        raise RuntimeError("Network restriction self-test failed; client was not launched")
    return True
