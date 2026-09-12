"""Restore operands of a deliberately small set of simple shell commands.

This is not a shell interpreter. Complex shell syntax and unknown programs stay
blocked. Re-encoding argv with shell quoting prevents restored confidential text
from becoming shell syntax or a new command-line option.
"""
import re
import shlex


class ShellRestoreBlocked(ValueError):
    pass


_OPTIONS = {
    "cat": {"-b", "-e", "-n", "-s", "-t", "-u", "-v"},
    "ls": {"-a", "-A", "-d", "-F", "-h", "-l", "-n", "-R", "-r", "-S", "-t", "-1"},
    "wc": {"-c", "-l", "-m", "-w"},
    "head": {"-q", "-v"},
    "tail": {"-q", "-v"},
    "file": {"-b", "-h", "-i", "-I", "-L"},
    "pwd": {"-L", "-P"},
    "cd": {"-L", "-P"},
}
_VALUE_OPTIONS = {"head": {"-n", "-c"}, "tail": {"-n", "-c"}}
_SYNTAX = re.compile(r"[\x00-\x1f\x7f$`;&|<>()*?\[\]{}~]")


def restore_simple_command(command, redactor):
    """Return a shell-quoted simple argv; never execute it here."""
    blocked = "Restoration requires a simple supported file-reading command."
    if not isinstance(command, str) or _SYNTAX.search(command):
        raise ShellRestoreBlocked(blocked)
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        raise ShellRestoreBlocked(blocked) from None
    if not words or words[0] not in _OPTIONS:
        raise ShellRestoreBlocked(blocked)
    program = words[0]
    result = [program]
    options_done = False
    expect_count = False
    operands = 0
    for word in words[1:]:
        changed = redactor.restore_text(word)
        if expect_count:
            if changed != word or re.fullmatch(r"[0-9]{1,8}", word) is None:
                raise ShellRestoreBlocked(blocked)
            expect_count = False
        elif not options_done and word == "--":
            options_done = True
        elif not options_done and word.startswith("-") and word != "-":
            if changed != word:
                raise ShellRestoreBlocked(blocked)
            if word in _VALUE_OPTIONS.get(program, set()):
                expect_count = True
            elif word not in _OPTIONS[program]:
                # Common grouped flags such as ls -la are still exact flags.
                if (not word.startswith("--") and len(word) > 2
                        and all("-" + flag in _OPTIONS[program] for flag in word[1:])):
                    pass
                else:
                    raise ShellRestoreBlocked(blocked)
        else:
            operands += 1
            # Option parsing may continue after operands in some utilities.
            # A restored secret cannot introduce an option even after '--'.
            if changed != word and (changed.startswith("-") or not changed
                                    or re.search(r"[\x00-\x1f\x7f]", changed)):
                raise ShellRestoreBlocked(blocked)
        result.append(changed)
    if expect_count or (program == "pwd" and operands) or (program == "cd" and operands != 1):
        raise ShellRestoreBlocked(blocked)
    return shlex.join(result)
