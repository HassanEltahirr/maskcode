"""Launch the installed Claude engine through MaskCode without reading its credentials."""
import json
import shutil

from .isolation import command, isolated_environment


class ClientConfigurationError(RuntimeError):
    """A native option would change the reviewed local client boundary."""


# New native options require review: a denylist cannot anticipate a future
# transport, host-process, settings, or plugin switch. These options only alter
# local interaction, supplied context, model choice, or built-in tool selection.
_FLAGS = frozenset({
    "--ax-screen-reader", "--continue", "-c", "--disable-slash-commands",
    "--exclude-dynamic-system-prompt-sections", "--fork-session", "--forward-subagent-text",
    "--help", "-h", "--include-hook-events", "--include-partial-messages", "--no-chrome",
    "--no-session-persistence", "--print", "-p", "--replay-user-messages", "--safe-mode",
    "--strict-mcp-config", "--verbose", "--version", "-v", "--json", "--text",
})
_VALUES = frozenset({
    "--append-system-prompt", "--append-system-prompt-file", "--autocompact", "--debug-file",
    "--effort", "--fallback-model", "--input-format", "--json-schema", "--max-budget-usd",
    "--max-turns", "--model", "--name", "-n", "--output-format", "--permission-mode",
    "--session-id", "--system-prompt", "--system-prompt-file",
})
_OPTIONAL = frozenset({
    "--debug", "-d", "--from-pr", "--resume", "-r", "--prompt-suggestions", "--worktree", "-w",
})
_MULTIPLE = frozenset({
    "--add-dir", "--allowedTools", "--allowed-tools", "--disallowedTools", "--disallowed-tools",
    "--tools",
})
_COMMANDS = frozenset({
    "agents", "auth", "auto-mode", "doctor", "gateway", "import", "install", "mcp",
    "plugin", "plugins", "project", "setup-token", "ultrareview", "update", "upgrade",
    "remote-control", "rc", "web", "desktop", "serve",
})
_READ_ONLY_COMMANDS = {("doctor",), ("auth", "status"), ("plugin", "list"),
                       ("plugins", "list"), ("mcp", "list"), ("auto-mode", "config"),
                       ("auto-mode", "defaults")}


def validate_claude_arguments(arguments):
    """Validate argv without changing what Claude receives or parsing prompts.

    Required option values may start with dashes. The standard -- delimiter is
    respected, as are native short option clusters such as -pc and -rSESSION.
    """
    values = list(arguments)
    positional = []
    index = 0
    while index < len(values):
        arg = values[index]
        if not isinstance(arg, str) or "\0" in arg:
            raise ClientConfigurationError("Invalid native argument")
        if arg == "--":
            positional.extend(values[index + 1:])
            break
        if not arg.startswith("-") or arg == "-":
            positional.append(arg)
            index += 1
            continue
        if not arg.startswith("--") and len(arg) > 2:
            # Expand only for validation. Preserve the original argv at launch.
            expanded = []
            for offset, letter in enumerate(arg[1:], 1):
                option = "-" + letter
                if option in _FLAGS:
                    expanded.append(option)
                elif option in _VALUES | _OPTIONAL:
                    expanded.append(option)
                    if arg[offset + 1:]:
                        expanded.append(arg[offset + 1:])
                    break
                else:
                    raise ClientConfigurationError("Native option is not supported by the protected launcher")
            values[index:index + 1] = expanded
            continue
        name, separator, inline = arg.partition("=")
        if name in _FLAGS:
            if separator:
                raise ClientConfigurationError("A native toggle cannot override the protected launcher")
            index += 1
            continue
        if name not in _VALUES | _OPTIONAL | _MULTIPLE:
            raise ClientConfigurationError("Native integration or unreviewed option blocked by MaskCode")
        consumed = []
        if separator:
            consumed.append(inline)
        elif name in _VALUES:
            index += 1
            if index >= len(values) or values[index] == "--":
                raise ClientConfigurationError("A native option is missing its value")
            consumed.append(values[index])
        elif name in _OPTIONAL:
            if index + 1 < len(values) and not values[index + 1].startswith("-"):
                index += 1
                consumed.append(values[index])
        else:
            while index + 1 < len(values) and not values[index + 1].startswith("-"):
                index += 1
                consumed.append(values[index])
            if not consumed:
                raise ClientConfigurationError("A native option is missing its value")
        if name == "--permission-mode" and consumed not in (
                ["default"], ["acceptEdits"], ["auto"], ["manual"], ["dontAsk"], ["plan"]):
            raise ClientConfigurationError("MaskCode requires native tool permission checks")
        index += 1
    if positional and positional[0] in _COMMANDS and tuple(positional) not in _READ_ONLY_COMMANDS:
        raise ClientConfigurationError("This native service or setup command must run outside MaskCode")


_AUTH_AND_PREFERENCES = frozenset({
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_FABLE_MODEL", "ANTHROPIC_SMALL_FAST_MODEL",
    "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_EFFORT_LEVEL", "CLAUDE_CODE_MAX_OUTPUT_TOKENS", "CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS",
    "CLAUDE_CODE_ACCESSIBILITY", "CLAUDE_AX_SCREEN_READER", "CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN",
    "CLAUDE_CODE_DISABLE_MOUSE", "CLAUDE_CODE_DISABLE_MOUSE_CLICKS", "CLAUDE_CODE_DISABLE_TERMINAL_TITLE",
})


def claude_environment(server):
    env = isolated_environment()
    for name in list(env):
        if (name.startswith(("CLAUDE_", "ANTHROPIC_", "OTEL_"))
                and name not in _AUTH_AND_PREFERENCES):
            del env[name]
    env.update({"ANTHROPIC_BASE_URL": server.proxy_url,
                # Documented gateway setting: omit attribution at the client
                # because masking can reshape system content. Never patch it.
                "CLAUDE_CODE_ATTRIBUTION_HEADER": "0",
                "CLAUDE_CODE_MAX_RETRIES": "0",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
                "CLAUDE_CODE_SAFE_MODE": "1", "DISABLE_AUTOUPDATER": "1",
                "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
                "CLAUDE_CODE_AUTO_CONNECT_IDE": "0", "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1",
                "CLAUDE_CODE_DISABLE_BG_EXIT_HANDOFF": "1", "CLAUDE_CODE_SKIP_REPO_UPLOAD": "1",
                "OTEL_SDK_DISABLED": "true", "OTEL_LOGS_EXPORTER": "none",
                "OTEL_METRICS_EXPORTER": "none", "OTEL_TRACES_EXPORTER": "none"})
    return env


def build_claude_command(server, extra):
    validate_claude_arguments(extra)
    return _protected_claude_command(server, extra)


def _protected_claude_command(server, extra):
    binary = shutil.which("claude")
    if not binary:
        raise RuntimeError("Claude Code is not installed; MaskCode uses its local engine and existing login")
    argv = [binary, "--safe-mode", "--no-chrome", "--strict-mcp-config",
            "--mcp-config", '{"mcpServers":{}}',
            "--setting-sources", "",
            "--settings", json.dumps({"skipWebFetchPreflight": True, "disableAllHooks": True}), *extra]
    return command(server.server_port, argv)


def build_claude_engine_command(server, extra):
    """Build the internal stdio transport; callers cannot replace its protocol.

    The permission-prompt switch is deliberately absent from the public native
    argument validator. Only this fixed, internal transport may enable it.
    Prompts travel over stdin, so positional commands and -- are not accepted.
    """
    validate_claude_arguments(extra)
    flags = {"--continue", "-c", "--fork-session", "--no-session-persistence",
             "--disable-slash-commands", "--exclude-dynamic-system-prompt-sections"}
    values = {"--model", "--fallback-model", "--effort", "--max-turns", "--max-budget-usd",
              "--system-prompt", "--system-prompt-file", "--append-system-prompt",
              "--append-system-prompt-file", "--session-id", "--name", "-n",
              "--permission-mode", "--autocompact"}
    optional = {"--resume", "-r", "--worktree", "-w"}
    multiple = {"--tools", "--allowedTools", "--allowed-tools", "--disallowedTools",
                "--disallowed-tools", "--add-dir"}
    index = 0
    while index < len(extra):
        name, separator, value = extra[index].partition("=")
        if name in flags and not separator:
            index += 1
            continue
        if name not in values | optional | multiple:
            raise ClientConfigurationError("This option is not supported by the MaskCode terminal")
        if not separator:
            if name in values:
                index += 1
            elif name in optional:
                if index + 1 < len(extra) and not extra[index + 1].startswith("-"):
                    index += 1
            else:
                while index + 1 < len(extra) and not extra[index + 1].startswith("-"):
                    index += 1
        index += 1
    return _protected_claude_command(server, [
        "--print", "--input-format", "stream-json", "--output-format", "stream-json",
        "--verbose", "--include-partial-messages", "--permission-prompt-tool", "stdio",
        "--permission-mode", "default", *extra,
    ])
