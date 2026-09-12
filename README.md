# MaskCode

MaskCode is an **experimental local privacy wrapper** for the installed Claude
Code or Codex CLI. A local Ollama model detects sensitive spans, rules replace
them with stable placeholders, and supported responses and tool arguments are
restored on your Mac. The installed agent can then read files, make edits, and run
commands and tests through its normal tool loop.

- **Claude backend:** an independent Hermes-inspired MaskCode terminal, with an
  amber interface, conversation, multiline composer, and tool activity.
- **Codex backend:** the installed Codex terminal, using the same local masking
  gateway. MaskCode's interface and slash commands are not yet available here.

**Detection is best effort and can miss confidential information.** Undetected
content can reach the cloud provider. Reversible masking is not a guarantee of
anonymity, zero disclosure, or full feature parity with the original clients.
Start with synthetic data and read the [privacy boundary](#privacy-boundary).

This build is reviewed for **personal use on your own Mac with your own account**.
MaskCode is independent and is not endorsed by Anthropic, OpenAI or Nous Research.
See [LEGAL_REVIEW.md](LEGAL_REVIEW.md) for the dated provider guidance and unresolved
legal questions. No universal legality or anonymity guarantee is made.

**Masking runs automatically in the background by default.** Ordinary coding
sessions do not stop to approve model-request JSON. Normal file and command
permissions remain active, with readable file, change, and command previews.
Use `--mask-review` when you want to inspect every outgoing request.
Ollama detects sensitive spans on your Mac, deterministic rules replace them with
stable placeholders, and the cloud model works on the masked context. Responses
and supported tool arguments are restored locally before the agent uses them.
Automatic detection can miss confidential information; it does not guarantee that
all sensitive content stays local. Fable and Astra still run at their providers.

## Quickstart

### 1. Install the prerequisites

The protected launcher currently supports **macOS only**, with `/usr/bin/sandbox-exec`
available. You need Python 3.10 or newer, Git, and the following separately installed
software:

- [Claude Code](https://code.claude.com/docs/en/quickstart) or
  [Codex CLI](https://learn.chatgpt.com/docs/cli), available on your shell's `PATH`.
  Use your own account with access to the selected provider and model.
  On macOS, MaskCode also finds the Codex executable bundled with `Codex.app` or
  `ChatGPT.app` in `/Applications` or `~/Applications`; a CLI on `PATH` takes
  precedence. Run `maskcode gateway doctor` to see the selected executable.
- [Ollama for macOS](https://docs.ollama.com/macos) and local
  [qwen2.5:1.5b weights](https://ollama.com/library/qwen2.5:1.5b).

Open the installed Ollama application, then explicitly download the local detector:

```sh
ollama pull qwen2.5:1.5b
```

This setup command downloads model weights. MaskCode does not download models
automatically or include vendor executables, credentials, or model weights.
Local detection needs no cloud API key; cloud coding still requires your own
provider access. Tested versions and hardware are listed in [VALIDATION.md](VALIDATION.md).

### 2. Install MaskCode in a virtual environment

```sh
git clone https://github.com/HassanEltahirr/maskcode.git
cd maskcode
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
maskcode --version
```

Activate this environment again in each new terminal before using `maskcode`.
The terminal dependencies are pinned to prompt_toolkit 3.0.52 and wcwidth 0.7.0.
The masking gateway itself uses the Python standard library.

### 3. Sign in through your chosen official client

For Claude:

```sh
claude auth login
```

For Codex:

```sh
codex login
```

If Codex is available only inside a desktop app, use the executable path reported
by `maskcode gateway doctor` for sign-in. For example:

```sh
"/Applications/ChatGPT.app/Contents/Resources/codex" login
```

MaskCode itself finds that bundled executable automatically; no shell PATH edit
is needed. Existing official authentication stays in place.

These are the providers' own sign-in flows. MaskCode does not supply an account,
subscription, or API credits. See [Authentication](#authentication) for recovery
and API-key behavior.

### 4. Open a project

Replace `/path/to/project` with a project you want the agent to work on. Begin with
a disposable project containing synthetic data. The first command opens the
MaskCode interface using your installed Claude configuration; the second opens
native Codex with the selected model:

```sh
maskcode --mask-cwd /path/to/project
maskcode --mask-backend codex --model gpt-6-astra --mask-cwd /path/to/project
```

More examples, subject to your provider's model access:

```sh
maskcode
maskcode --mask-cwd /path/to/project
maskcode --model sonnet 'explain this project'
maskcode --mask-cwd /path/to/project 'fix the failing tests and run them'
maskcode --model claude-fable-5-1
maskcode --mask-backend codex --model gpt-6-astra
maskcode --mask-policy /path/to/private-policy.json
maskcode --mask-review
maskcode --resume SESSION_ID
maskcode --continue
```

The interface is inspired by [Hermes Agent](https://github.com/NousResearch/hermes-agent).
It is an independent MaskCode implementation, with no Hermes runtime bundled.
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for sources and license notices.
The upstream Claude executable is not patched or renamed.

MaskCode starts and stops its own protected Ollama process, reusing your installed
model files. It leaves an existing Ollama service alone. The first scan loads the
model and can take tens of seconds; unchanged scan chunks are cached in memory.
Once loaded, the detector stays resident for the MaskCode session instead of
unloading after an idle timeout. This keeps its model memory allocated until you
exit MaskCode; the owned process still stops on normal exit.
The Claude interface shows local scanning progress. Native Codex shows its own
Working timer across local masking and the buffered cloud reply; it has no live
MaskCode progress callback. Its launcher explains this before startup and prints
numeric local-scan timing after Codex exits. A failed or invalid local scan blocks
that request, with no automatic cloud fallback. Choose another installed detector
with `--mask-local-model NAME`; `--mask-rules-only` explicitly disables AI detection.
It does not download models automatically.

For Codex, the launcher recognizes the exact public base instructions from the
installed client's bundled model catalog. Only an identical top-level instruction
string for that model skips local AI extraction. Deterministic masking still runs
on it; edited instructions, prompts, files, tool definitions/results, and nested
copies continue through detection. This avoids repeatedly classifying the same
public instructions. It does not remove the initial model load or cloud latency.

Normal exit, SIGTERM and terminal hangup clean up owned processes. SIGKILL or an
interpreter crash can prevent cleanup; the gateway does not claim crash-proof
process or memory erasure.

On 2026-09-13, Astra passed one live synthetic echo round trip with exact local
restoration. The Fable 5.1 live check did not pass: the provider returned HTTP 429.
The current read/edit/test integration checks use fixture providers; the Astra
echo is not a live coding-loop result. See [VALIDATION.md](VALIDATION.md) for the
exact evidence. MaskCode cannot remove account limits or guarantee model access;
provider errors remain visible. The Claude launcher disables automatic retry loops.

## Terminal controls

- **Enter** sends; **Alt+Enter / Ctrl+J** inserts a line.
- **Tab** completes slash commands; arrow keys navigate prompt history.
- **Ctrl+C** interrupts work or cancels an input draft; **Ctrl+D** exits an empty prompt.
- `/help` shows commands, `/model` shows or changes the model, `/clear` clears the
  displayed conversation, `/privacy` shows masking status, and `/quit` exits.
- `/about` shows credits, independence, and the personal-use scope.
- **F5** or `/restart` starts a fresh protected conversation; F5 keeps your unsent
  draft without submitting it. Files already edited on disk stay in place.
  `/login` opens official Claude sign-in, then returns to a fresh MaskCode session.
  Interrupt an active turn before restarting or signing in.
- Review dialogs keep the exact request available for scrolling and default to
  denial. **Tab** selects Approve or Deny; **Enter** confirms; **Esc** denies;
  **Page Up / Page Down** scrolls the request. They never approve on timeout.
  **Ctrl+O** toggles complete tool input in a tool permission dialog.
  The underlying Claude permission policy
  can allow ordinary tools without a callback; actions needing permission appear
  as separate tool approval dialogs.

Prompt history stays in memory in the MaskCode interface. Claude's own local
session persistence remains enabled unless `--no-session-persistence` is supplied.
Clearing the displayed conversation does not reset the underlying session.
Absolute file paths can start a prompt, for example
`/path/to/project/main.py fix the failing function`. If the engine exits, pending
approval dialogs close and the composer keeps your draft for recovery.

## Options and compatibility

| Option | Behavior |
| --- | --- |
| `--mask-policy FILE` | Add confidential literal values and regex patterns |
| `--mask-local-model NAME` | Choose the installed Ollama detector; default `qwen2.5:1.5b` |
| `--mask-rules-only` | Explicitly disable local AI detection and keep masking rules |
| `--mask-backend claude\|codex` | Claude uses MaskCode's interface; Codex uses its native interface |
| `--mask-cwd DIRECTORY` | Choose the project directory |
| `--mask-review` | Inspect and approve each outgoing model request |
| `--mask-auto` | Mask and forward in the background (default) |
| `--mask-dashboard` | Also open the optional local browser companion |
| `--mask-port NUMBER` | Choose the local gateway port |
| `--mask-native` | Use the original Claude Code terminal instead of MaskCode's UI |
| `--help`, `--version` | Show MaskCode help and version |

Supported model, session, prompt and tool-selection options are passed to the
installed Claude engine. Settings/plugin/transport overrides, permission bypasses
and unreviewed native switches fail closed. The protected engine still uses safe
mode: customizations, plugins, MCP, hooks and remote features remain restricted.
Changing the terminal appearance does not remove those protections.

Print and structured output modes continue to use the native path:

```sh
maskcode -p 'explain this function'
maskcode -p 'summarize' --output-format json
maskcode --mask-native
maskcode --mask-native --help
```

The native path keeps stdin/stdout/stderr attached directly, with no rebranding
filter or terminal emulator. In native/print review mode, approvals use the browser
companion; the MaskCode interface handles review in the terminal.

## Authentication

Sign in before starting MaskCode:

```sh
maskcode auth login
```

MaskCode uses the official CLI's authentication. It does not extract credentials
from storage or create API credits. An API-key environment variable can select
API billing instead of a Claude subscription. The selected executable follows
PATH; `maskcode --mask-native --version` identifies it. If multiple Claude
installations exist, the version can differ between shells.

Use `/login` in the terminal to refresh an expired login. MaskCode closes its
coding session and opens the installed CLI's exact `claude auth login` command;
the official CLI owns that separate sign-in flow. MaskCode does not capture its
input, output or credentials. Afterwards, MaskCode opens a fresh protected session
and preserves any unsent draft without sending it. Cancelling sign-in also returns
to the terminal. You can still run `claude auth login` directly.

The first forwarded inference request pins the session's authentication header
set; changed credentials require a fresh session. `/restart` recreates the engine
and gateway, checks network restrictions again, and preserves model preferences.
Recovery does not replay a previous task, tool action or conversation, including
one originally started with `--resume` or `--continue`. Account authentication
still reaches the provider and identifies the account.

Recovery reuses the working directory reported by the engine, including a
worktree, and does not create another worktree. If restarted before the engine
has reported its worktree directory, it uses the original project directory and
shows that explicitly.

The official client's login remains intact; MaskCode does not supply a login page,
share accounts, pool usage, or bypass provider limits. Anthropic documents using a
saved personal subscription through an `ANTHROPIC_BASE_URL` gateway. This is not
permission to host subscription access for others; see the review above.

## Configure confidential values locally

Copy `examples/policy.example.json` to a private location outside source control:

```json
{
  "literals": [
    {"value": "Cedar Example LLC", "label": "ORG", "ignore_case": true,
     "normalize": true, "encodings": ["url", "base64"]},
    {"value": "Nadia Example", "label": "PERSON", "ignore_case": true}
  ],
  "patterns": [{"regex": "CASE-[0-9]{8}", "label": "CASE"}]
}
```

Literal matching is exact unless options enable case/Unicode variants or bounded
single-layer URL/base64 inspection. Encoded candidates above 64 KiB fail closed.
This does not detect arbitrary obfuscation, partial names or sensitive meaning.
Every recognized variant restores to its exact local original. Locally discovered
spans also receive bounded URL/base64 variant checks. The local AI adds exact spans
to the same memory-only mapping; it never rewrites source code or invents replacement
values. Explicit policy remains useful for terms the detector misses.

Built-ins cover email addresses, international/UAE phone patterns, Emirates IDs,
selected API keys, private keys, credential fields, IPv4 addresses excluding
loopback by default, and Luhn-valid cards. The launcher adds your home-directory
path. Sensitive numeric fields are blocked rather than changing JSON types.
Residual checks reject known protected data left after masking. Duplicate JSON
keys, nonfinite values and ambiguous key substitutions fail closed.

```sh
maskcode gateway demo
printf '%s\n' 'Contact demo@example.com' | maskcode gateway preview
maskcode gateway preview --policy /path/to/private-policy.json < local-input.txt
maskcode gateway doctor
```

Preview is offline and rules-only; it does not run the Ollama detector.
Avoid putting real secrets into shell arguments or history.
The browser preview's extra terms apply only to that preview; save a policy file
to apply terms to the actual coding session.

## Privacy boundary

```text
Files / prompt → official agent → rules → local Ollama span detection
                                              ↓
                                 stable placeholder replacement
                                              ↓
                         cloud model receives masked context
                                              ↓
                      exact local restoration → agent edits / tests
```

- Model routes are fixed, loopback capabilities authenticated, and arbitrary
  headers/metadata omitted. Provider auth is necessary; its keyed session
  fingerprint prevents later header changes from becoming a new data channel.
- The launcher verifies direct sockets to its gateway succeed and other
  loopback/public destinations are blocked. Startup fails without enforcement.
  It disables inherited injection knobs, unsafe customizations and alternate
  transports. There is no direct-provider fallback.
- The local detector runs in a separate process with external TCP/UDP sockets
  blocked and model files read-only. Loopback TCP remains available for Ollama's
  internal runner. Its temporary state is cleaned up at exit. This is not a
  hardened boundary against OS-helper IPC, hostile local services, or OS swap.
- The detector validates exact spans against the supplied source, uses a bounded
  JSON schema, and rejects invalid output. Authentication is excluded from the
  detector. Known secrets are masked before detection. Model output cannot choose
  placeholders, rewrite code, or decide to bypass the gateway.
- Fixed public protocol/schema vocabulary and generated transport framing are
  excluded from AI entity discovery. This prevents ordinary words such as
  `function` from corrupting tool definitions. Explicit policies and deterministic
  validation still apply; unknown names, prompts, file data and tool results are
  still inspected.
- Because masking can change system content, the client uses the documented
  `CLAUDE_CODE_ATTRIBUTION_HEADER=0` gateway setting. The gateway does not forge
  an attribution block or provider credentials.
- `sandbox-exec` is deprecated. It does not provide a hardened filesystem or
  OS-helper IPC boundary against hostile same-user software, and it does not
  protect other desktop/browser/terminal sessions.
- Anthropic text streams incrementally. Tool blocks and following events wait
  for complete validation and clean upstream EOF. Interrupted streams may leave
  partial display text, but do not release partial tools or successful completion.
- Structured file paths and file contents can be restored. Shell substitutions
  are limited to quoted operands in simple `cat`, `ls`, `head`, `tail`, `wc`,
  `file`, `pwd` and `cd` commands. Option injection, shell programs and interpreter
  source remain blocked. Normal tool permission checks still apply.
- Codex's standard local function calls and freeform `apply_patch` are supported.
  Patch framing and individual restored lines are validated before release; a
  placeholder cannot introduce a new patch operation or shell command.
- Media/uploads, remote hosted tools, opaque unverified history and server-side
  conversation references are blocked. Signed reasoning can replay only from the
  same gateway session; resuming older signed history may fail in a new gateway.
- Request/response limits are 8/32 MiB. The local scan has an additional limit of
  262,144 text characters per request and 128 chunks; exceeding a limit blocks
  forwarding. Maps and scan caches stay in gateway memory; no plaintext
  vault or request/auth logs are written. Originals can remain in Claude's local
  history, terminal/browser memory, source files, swap and crash dumps.

This local anonymizer cannot guarantee detection of all confidential information or
preserve every unrestricted agent feature. Optional request review helps control
what is sent; it cannot make an unmasked fact private after transmission.
The reversible placeholders provide pseudonymization, not a determination that
the data is legally anonymous. Owning a subscription does not establish permission
to upload client, employer, or other people's confidential data.

## Other providers

`maskcode --mask-backend codex --model gpt-6-astra` launches the installed Codex
client through the same local detector and masking gateway. It preserves official
Codex authentication and uses the model catalog bundled with that installed CLI.
Sign in with `codex login` separately if needed. The temporary provider/catalog
settings are removed when the client exits; saved user configuration is unchanged.

The Codex path currently displays the native Codex terminal. MaskCode's own Hermes-
inspired interface and its slash commands are for the Claude backend. Codex uses
standard Responses function/patch tools, with hosted tools, plugins, hooks and
alternate transports disabled. OpenAI responses are buffered before restoration.
If the Codex subscription endpoint omits its response MIME header, MaskCode
requires a complete, strictly validated Responses event stream before releasing
it. Explicit unsupported content types remain blocked.
See validation for the exact tested provider coverage.

On macOS, Codex uses one outer MaskCode sandbox because nested native sandboxes
prevent its command tools from running. That sandbox permits direct sockets only
to the gateway and writes only to the chosen project, explicitly added directories,
private temporary directory and official Codex state directory. Reads elsewhere
remain possible. Codex's internal sandbox is disabled only inside this outer
restriction; its approval policy remains `on-request`. User sandbox/configuration
overrides are rejected. This does not provide a hardened OS-helper IPC boundary.

`maskcode gateway serve --provider openai` exposes a fixed OpenAI Responses
upstream for normally authenticated API clients; it does not turn a ChatGPT
subscription into API credits.

## Validation

See [VALIDATION.md](VALIDATION.md) for current test evidence and limitations.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, synthetic test
fixtures, and safe bug reports. MaskCode's source is available under the
[MIT License](LICENSE). Third-party clients, libraries, and model weights retain
their own licenses and terms; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
