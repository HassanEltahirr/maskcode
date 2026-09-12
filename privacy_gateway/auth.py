"""Explicit handoff to the installed Claude CLI's official sign-in flow.

The caller must close its protected coding session before invoking this helper.
MaskCode never receives the login's input, output, or credentials.
"""
import shutil
import subprocess
import sys

from .isolation import isolated_environment


_LOGIN_PREFERENCES = frozenset({
    "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_ACCESSIBILITY", "CLAUDE_AX_SCREEN_READER",
    "CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN", "CLAUDE_CODE_DISABLE_MOUSE",
    "CLAUDE_CODE_DISABLE_MOUSE_CLICKS", "CLAUDE_CODE_DISABLE_TERMINAL_TITLE",
})


def official_login(cwd):
    """Run an explicitly requested official login, returning its exit status.

    Standard input, output, and error stay attached to the user's terminal.
    Authentication and gateway overrides are excluded from this separate flow;
    HOME and CLAUDE_CONFIG_DIR keep the user's normal credential store selected.
    """
    try:
        binary = shutil.which("claude")
        if not binary:
            print("MaskCode: Claude Code is not installed. Install the official Claude CLI, then run maskcode auth login.",
                  file=sys.stderr)
            return 127
        env = isolated_environment()
        for name in list(env):
            if (name.startswith(("ANTHROPIC_", "CLAUDE_", "OTEL_"))
                    and name not in _LOGIN_PREFERENCES):
                del env[name]
        print("Opening the official Claude sign-in flow...", flush=True)
        result = subprocess.run([binary, "auth", "login"], cwd=cwd, env=env,
                                check=False, close_fds=True)
    except KeyboardInterrupt:
        return 130
    except OSError:
        print("MaskCode could not open the official Claude sign-in flow. Check the Claude installation and project directory, then retry maskcode auth login.",
              file=sys.stderr)
        return 1
    if result.returncode:
        print("MaskCode: Official Claude sign-in did not complete. Run maskcode auth login to try again.",
              file=sys.stderr)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode
