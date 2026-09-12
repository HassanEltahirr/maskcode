"""Protected launch of the installed Codex CLI through MaskCode's gateway.

A temporary model catalog selects Codex's standard Responses transport and local
function/patch tools. It preserves the selected model and its instructions; no
vendor executable or saved user configuration is modified. The running client
keeps its original authentication source, including ChatGPT subscription login.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import tempfile

from .client import ClientConfigurationError
from .isolation import command, isolated_environment
from .codex_isolation import command as codex_command


class CodexConfigurationError(ClientConfigurationError):
    pass


_FLAGS = frozenset({"--no-alt-screen", "--json", "--ephemeral", "--skip-git-repo-check",
                    "--ignore-user-config", "--ignore-rules", "--help", "-h", "--version", "-V"})
_VALUES = frozenset({"--model", "-m", "--ask-for-approval", "-a",
                     "--cd", "-C", "--add-dir", "--color", "--output-schema",
                     "--output-last-message", "-o"})
_AUTH_ENV = frozenset({"CODEX_HOME", "CODEX_API_KEY", "OPENAI_API_KEY"})


def _macos_codex_paths():
    """Known desktop bundle locations; never search project files for a client."""
    return tuple(directory / app / "Contents" / "Resources" / "codex"
                 for app in ("Codex.app", "ChatGPT.app")
                 for directory in (Path("/Applications"), Path.home() / "Applications"))


def find_codex_binary():
    """Prefer the user's PATH, then the CLI in standard macOS app bundles."""
    binary = shutil.which("codex")
    if binary:
        return os.path.abspath(binary)
    if platform.system() == "Darwin":
        for candidate in _macos_codex_paths():
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate.absolute())
    return None


def validate_codex_arguments(arguments):
    """Return (unchanged argv, selected model, exec argv index or None) after strict validation.

    Configuration/profile/remote/provider switches cannot replace the gateway.
    Only the interactive CLI and ``exec`` are supported; service/setup commands
    must run independently of MaskCode.
    """
    values = list(arguments)
    model = "gpt-6-astra"
    exec_position = None
    positionals = []
    index = 0
    while index < len(values):
        arg = values[index]
        if not isinstance(arg, str) or "\0" in arg:
            raise CodexConfigurationError("Invalid Codex argument")
        if arg == "--":
            positionals.extend(values[index + 1:])
            break
        if not arg.startswith("-") or arg == "-":
            if arg in ("exec", "e") and not positionals and exec_position is None:
                exec_position = index
            else:
                positionals.append(arg)
            index += 1
            continue
        name, separator, value = arg.partition("=")
        if name in _FLAGS and not separator:
            index += 1
            continue
        if name not in _VALUES:
            raise CodexConfigurationError("Codex integration or configuration override blocked by MaskCode")
        if not separator:
            index += 1
            if index >= len(values) or values[index] == "--":
                raise CodexConfigurationError("A Codex option is missing its value")
            value = values[index]
            if isinstance(value, str) and value.startswith("-"):
                raise CodexConfigurationError("Codex option values beginning with a dash require the equals form")
        if not isinstance(value, str) or "\0" in value or not value:
            raise CodexConfigurationError("Invalid Codex option value")
        if name in ("--model", "-m"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
                raise CodexConfigurationError("Invalid Codex model name")
            model = value
        elif name in ("--ask-for-approval", "-a") and value != "on-request":
            raise CodexConfigurationError("MaskCode requires Codex tool permission checks")
        elif name == "--color" and value not in ("auto", "always", "never"):
            raise CodexConfigurationError("Invalid Codex color option")
        index += 1
    if any(not isinstance(value, str) or "\0" in value for value in positionals):
        raise CodexConfigurationError("Invalid Codex prompt")
    if len(positionals) > 1:
        raise CodexConfigurationError("Pass one Codex prompt; unsupported commands are blocked")
    # These tokens are parsed by Codex as subcommands even when the wrapper
    # considers them a positional. An explicit -- keeps them literal prompts.
    commands = {"agents", "review", "login", "logout", "mcp", "plugin", "mcp-server", "app-server",
                "remote-control", "app", "completion", "update", "doctor", "sandbox", "debug",
                "apply", "resume", "queue", "archive", "delete", "migrate-rollouts", "unarchive",
                "fork", "cloud", "exec-server", "features", "help"}
    if "--" not in values and positionals and positionals[0] in commands:
        raise CodexConfigurationError("Run Codex service, setup, and history commands outside MaskCode")
    return values, model, exec_position


def codex_environment(environ=None):
    """Preserve official auth; remove inherited transport and loader overrides."""
    env = isolated_environment(environ)
    for name in list(env):
        if name.startswith(("CODEX_", "OPENAI_", "CHATGPT_", "OTEL_")) and name not in _AUTH_ENV:
            del env[name]
    env.update({"OTEL_SDK_DISABLED": "true", "OTEL_LOGS_EXPORTER": "none",
                "OTEL_METRICS_EXPORTER": "none", "OTEL_TRACES_EXPORTER": "none"})
    return env


def _read_bundled_model(binary, port, directory, selected):
    # Metadata discovery has no need for authentication or user configuration.
    # Give this read-only bundled-catalog command its own temporary cache.
    metadata_env = {key: value for key, value in isolated_environment().items()
                    if key in {"PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR"}}
    metadata_env.update({"HOME": str(directory), "CODEX_HOME": str(directory), "NO_COLOR": "1"})
    try:
        result = subprocess.run(command(port, [binary, "debug", "models", "--bundled"]),
                                cwd=directory, env=metadata_env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=15, close_fds=True)
        if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
            raise ValueError()
        catalog = json.loads(result.stdout)
        entries = catalog.get("models") if isinstance(catalog, dict) else None
        if not isinstance(entries, list):
            raise ValueError()
        selected_models = [entry for entry in entries if isinstance(entry, dict) and entry.get("slug") == selected]
        if len(selected_models) != 1:
            raise CodexConfigurationError("The selected model is absent from the installed Codex catalog; update Codex or choose a listed model")
        model = copy.deepcopy(selected_models[0])
    except CodexConfigurationError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        raise CodexConfigurationError("The installed Codex CLI could not supply its bundled model catalog; update Codex before using this adapter") from None
    model.update({
        "use_responses_lite": False,
        "tool_mode": "direct",
        "node_repl_disabled": True,
        "experimental_supported_tools": [],
        "supports_search_tool": False,
    })
    # Keep freeform apply_patch. MaskCode validates/restores that patch format
    # explicitly; suppressing it would force edits into opaque shell programs.
    return model


def _settings(provider, base_url, catalog_path, model):
    prefix = "model_providers." + provider + "."
    values = {
        "model": model,
        "model_provider": provider,
        "model_catalog_json": str(catalog_path),
        prefix + "name": "MaskCode",
        prefix + "base_url": base_url,
        prefix + "requires_openai_auth": True,
        prefix + "wire_api": "responses",
        prefix + "supports_websockets": False,
        prefix + "request_max_retries": 0,
        prefix + "stream_max_retries": 0,
        prefix + "stream_idle_timeout_ms": 3600000,
        # The fixed outer profile enforces filesystem writes and network. A
        # second native Seatbelt sandbox cannot be applied inside that process.
        "sandbox_mode": "danger-full-access",
        "approval_policy": "on-request",
        "mcp_servers": {},
        "hooks": {},
        "web_search": "disabled",
        "apps._default.enabled": False,
        "analytics.enabled": False,
        "otel.exporter": "none",
        "otel.trace_exporter": "none",
        "otel.metrics_exporter": "none",
        "otel.log_user_prompt": False,
        "check_for_update_on_startup": False,
        "features.enable_request_compression": False,
        "features.unbounded_connection_retries": False,
        "features.apps": False,
        "features.plugins": False,
        "features.hooks": False,
        "features.remote_plugin": False,
        "features.browser_use": False,
        "features.browser_use_external": False,
        "features.computer_use": False,
        "features.in_app_browser": False,
        "features.image_generation": False,
        "features.view_image": False,
        "features.shell_snapshot": False,
        "features.memories": False,
        "features.skill_search": False,
        "features.skill_mcp_dependency_install": False,
        "features.skip_host_skill_discovery": True,
    }
    return values


@contextmanager
def protected_codex_launch(server, arguments, *, cwd=None):
    """Yield (sandboxed argv, env); keep the temporary catalog until child exit."""
    extra, selected, exec_position = validate_codex_arguments(arguments)
    base_cwd = Path(cwd or Path.cwd()).expanduser().resolve(strict=True)
    effective_cwd = base_cwd
    additional = []
    index = 0
    while index < len(extra):
        arg = extra[index]
        if arg == "--":
            break
        name, separator, value = arg.partition("=")
        if name in _VALUES:
            if not separator:
                index += 1
                value = extra[index]
            if name in ("--cd", "-C", "--add-dir"):
                candidate = Path(value).expanduser()
                if name in ("--cd", "-C"):
                    effective_cwd = (candidate if candidate.is_absolute() else base_cwd / candidate).resolve(strict=True)
                    if not effective_cwd.is_dir():
                        raise CodexConfigurationError("A Codex workspace directory does not exist")
                else:
                    additional.append(candidate)
        index += 1
    additional = [(path if path.is_absolute() else effective_cwd / path).resolve(strict=True) for path in additional]
    if not effective_cwd.is_dir() or any(not path.is_dir() for path in additional):
        raise CodexConfigurationError("A Codex workspace directory does not exist")
    binary = find_codex_binary()
    if not binary:
        raise CodexConfigurationError(
            "Codex was not found on PATH or in standard macOS app locations. "
            "Install the official Codex CLI or desktop app, then retry.")
    with tempfile.TemporaryDirectory(prefix="maskcode-codex-") as temporary:
        directory = Path(temporary)
        model = _read_bundled_model(binary, server.server_port, directory, selected)
        path = directory / "models.json"
        path.write_text(json.dumps({"models": [model]}, ensure_ascii=False), encoding="utf-8")
        path.chmod(0o600)
        # A random per-launch provider avoids inheriting auth commands or HTTP
        # headers from a similarly named provider in existing user settings.
        provider = "maskcode_" + secrets.token_hex(8)
        argv = [binary]
        for key, value in _settings(provider, server.proxy_url, path, selected).items():
            argv.extend(["-c", key + "=" + json.dumps(value)])
        if exec_position is not None:
            # These official exec switches preserve auth while skipping user
            # config/rules. Insert them immediately after the exec command;
            # inserting after a user -- would turn flags into prompt text.
            extra = extra[:exec_position + 1] + ["--ignore-user-config", "--ignore-rules"] + extra[exec_position + 1:]
        argv.extend(extra)
        env = codex_environment()
        state_directory = Path(env.get("CODEX_HOME", str(Path.home() / ".codex"))).expanduser()
        state_directory = (state_directory if state_directory.is_absolute() else base_cwd / state_directory).resolve()
        scratch = directory / "scratch"
        scratch.mkdir(mode=0o700)
        env.update({"TMPDIR": str(scratch), "TMP": str(scratch), "TEMP": str(scratch)})
        yield codex_command(server.server_port, argv, [effective_cwd, *additional],
                            directory, state_directory), env
