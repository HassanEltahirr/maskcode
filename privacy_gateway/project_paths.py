"""Exact masking rules for locally selected directories, never their parents."""
from dataclasses import replace
import os
from pathlib import Path


_SHARED_ROOTS = frozenset({
    "/", "/private", "/var", "/private/var", "/tmp", "/private/tmp",
    "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders",
    "/Users", "/home", "/Volumes", "/System", "/System/Volumes", "/System/Volumes/Data",
    "/Library", "/Applications",
    "/usr", "/etc", "/private/etc", "/opt", "/bin", "/sbin", "/dev",
    "/proc", "/sys", "/run",
})


def directory_literals(paths, label="LOCAL_PROJECT"):
    """Normalize explicit roots, retaining a selected symlink spelling too.

    A canonical project path and its absolute lexical spelling can both appear
    in native context. No parent, temporary container, or auth path is inferred.
    """
    result, seen = [], set()
    try:
        for value in paths:
            path = Path(value).expanduser()
            absolute = Path(os.path.abspath(path))
            canonical = path.resolve(strict=True)
            if not canonical.is_dir():
                raise ValueError()
            canonical_root = str(canonical)
            # macOS can expose the same shared roots beneath its Data volume.
            if canonical_root.startswith("/System/Volumes/Data/"):
                canonical_root = canonical_root[len("/System/Volumes/Data"):]
            if (canonical.parent == canonical or str(canonical) in _SHARED_ROOTS
                    or canonical_root in _SHARED_ROOTS or str(absolute) in _SHARED_ROOTS):
                continue
            for candidate in (canonical, absolute):
                text = str(candidate)
                if text not in seen and text not in _SHARED_ROOTS:
                    seen.add(text)
                    result.append((text, label))
    except (OSError, ValueError, TypeError, RuntimeError):
        raise ValueError("A selected local directory could not be protected.") from None
    return result


def with_directory_literals(policy, literals):
    """Keep configured labels and add each exact path at most once."""
    known = {value for value, _ in policy.literals}
    additions = []
    for value, label in literals:
        if value not in known:
            known.add(value)
            additions.append((value, label))
    return replace(policy, literals=policy.literals + tuple(additions)) if additions else policy


def register_project_directories(state, paths):
    """Add launch-selected roots before requests without reissuing vault tokens."""
    literals = directory_literals(paths)
    with state._scan_lock, state.lock, state.redactor._lock:
        if state.closed or state._scan_started or state.requests or state.forwarded:
            raise ValueError("Project directories must be protected before requests.")
        policy = with_directory_literals(state.policy, literals)
        # Only exact literals change. Existing encoded/regex rules and issued
        # mappings remain intact, and request discovery shares this scan lock.
        state.policy = policy
        state.redactor.policy = policy
