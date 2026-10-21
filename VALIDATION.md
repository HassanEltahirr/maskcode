# MaskCode validation

## 1.0.0 — private chat app

`maskcode app` (and the `Start MaskCode` launchers) opens a ChatGPT-style chat in
the browser. Messages are masked on a loopback server, only masked history goes
to the configured provider (OpenAI-compatible Chat Completions or Anthropic
Messages, streamed), and replies are restored before display; partial
placeholders are held back while streaming. Each message can show its masked
version. `tests/test_chat.py` uses a local fake provider to assert the provider
never receives configured words or emails, the reply is restored, follow-up
history stays masked, keys are never returned to the browser, and plain HTTP is
refused for remote hosts. `tests/test_app.py` covers loopback binding, the
per-launch token, Host/Origin checks and word storage. Exercised end to end on
Windows 11 against a live GPT model: multi-turn chat, restored replies, masked
views, markdown rendering, and escaping of HTML in model output.

## 0.9.0 — broader built-ins and offline scan

Added rules-only detectors for GitLab, Hugging Face, npm, PyPI, Google OAuth,
SendGrid, Shopify, DigitalOcean and Slack app tokens; Slack, Teams and Discord
webhook URLs; `AccountKey`/`SharedAccessKey` credential fields; and IBANs that
pass the ISO 13616 mod-97 check (invalid checksums and ordinary uppercase words
are left alone). `maskcode gateway scan` reports file, label and line numbers
without values. `tests/test_builtins_extended.py` covers masking, exact
restoration, IBAN false positives, value-free reports and exit codes with
synthetic fixtures only. The existing redaction, security, server, protocol and
semantic suites pass unchanged. CI now runs on Python 3.10, 3.12 and 3.13.

## 0.8.0 — streaming and response latency

Codex now receives incrementally restored display text, including text after
opaque reasoning. Tool events, all events following a tool, and successful
completion remain held until clean upstream EOF and full stream/patch validation.
The installed Codex client emitted a restored synthetic message before the
fixture provider finished its response. Interrupted streams can display partial
text; they cannot release unvalidated tools or successful completion.

Local scanning reuses identical batches after conversation items move. In a
synthetic four-source conversation, adding one short question caused nine new
detector calls before this change and one afterward (eight cache hits). This
measures call reuse, not a claimed nine-fold wall-clock speedup. Changed source
text, dictionary context, nesting, and batch contents still require scans.
Exact, previously validated short-batch layouts now remain reusable after short
insertions too. Layout metadata is hash-only, bounded, and evicted with its cache
entry. Repair results use a separate key that includes the repair instructions.
If cached layouts would fragment a small request beyond the chunk limit, planning
retries once with ordinary batching. Real input and chunk limits still block.

Recoverable invalid detector dictionaries receive at most one local retry with the same
source and schema plus a fixed validation reminder. Rejected content is never
added to the prompt. Tests cover invalid-then-valid reuse, invalid-then-invalid,
timeout, closure, source/context changes, token protection, and cache bounds.
Runtime errors and timeouts are not retried; failed validation still blocks.
Individually valid first-attempt spans are retained only after a complete repair
validates, with combined entity limits enforced. A repair cannot silently discard
a previously detected sensitive span.
Oversized entity lists block before repair. Prompt guidance distinguishes ordinary
programming counts, indices, timeouts, exit codes and test constants from
contextually confidential identifiers and amounts; numeric gateway checks remain
unchanged.

A real local-model fixture exposed repeated classification of placeholder
fragments. The detector's input now replaces only already-protected placeholder
characters with equal-length spaces, including split tokens at chunk edges.
Surrounding text stays intact. Validation still checks the original source and
protected ranges; cache keys include both original identity and exact detector
input. Invalid token claims still block if the model invents them.

Actual Codex fixtures also exposed discovery of fixed roles, token-limit numbers
in replayed provider tool calls, and generated protocol IDs. Public role and
built-in tool vocabulary is excluded only from semantic discovery; explicit
policies still apply. Codex drops exact native lowercase UUIDv7 bookkeeping IDs
only from direct input messages and function/custom tool outputs (`msg_`, `fco_`,
`ctco_`). Tool correlation IDs, output content, arbitrary IDs, nested copies and
non-Codex requests retain their checks.

A separate bounded registry admits only typed IDs and exact Codex tool-call cores
from completely validated provider replies, after clean stream EOF. It stores
at most 2,048 hashes; identifiers are bounded to 256 characters and call bodies to
256 Ki characters. The local discovery view can omit matching direct replay
fields. Both raw arguments and their exact sanitizer-produced compact JSON form
are recognized, with duplicate keys/nonfinite values rejected and key order
preserved. Changed body/name/call ID/namespace, unknown keys, changed metadata,
content copies and all tool results remain inspected. The outgoing payload still
passes deterministic masking before and after discovery. Close clears the
registry; late stream callbacks cannot repopulate a closed session.

The protected detector now loads without a prompt in the background as the
terminal opens. In the final local probe, `prewarm()` returned in 0.000392 s, cold
loading finished in 69.799 s, and the following synthetic person/company extraction
completed correctly in 1.117 s. Loading overlaps setup and typing; an immediate
request still waits. Loading remains variable on this Mac. CPU mode still incurred GPU initialization
and processed 4,000-character chunks more slowly, while the separately installed
Ollama app 0.34.0 failed protected startup readiness. Neither was adopted.
The working Ollama selection and network boundary are unchanged; owned resources
were confirmed closed after the probes.

An earlier generation-based warmup failed during the first live coding probe,
blocking the request before any cloud call. Its cause was not established; a
separate diagnostic succeeded. Warmup now uses Ollama's explicit promptless
load-only operation and is advisory: a failed warmup permits a later actual
local scan, which must still succeed and validate completely before forwarding.

`--mask-effort` explicitly selects a reasoning budget supported by the installed
Codex model. The installed synthetic subscription test verified `medium` in both
the native request and the masked outgoing request. Omitting the option preserves
the existing setting; model and service tier are unchanged.

Selected project roots are automatically protected even outside the home
directory, including explicit Codex project/additional roots and symlink spellings.
Shared filesystem roots are excluded. A socket reset detected after scanning
blocks forwarding; a valid write-half-closed client still receives its response.
This does not guarantee cancellation for every disconnect or remove transport
races. Disconnecting during response headers closes the owned upstream iterator.

The complete suite ran **459 tests in 38.628 s: 457 passed and two optional local
model tests skipped**, with both installed-client opt-ins enabled. Installed CLI
tests use synthetic credentials and fixture providers. Separate real-model and
live-provider evidence is recorded below.

The 0.8.0 wheel built offline with existing setuptools. All 25 source modules,
the browser companion, command entry points and complete license/review files
were present; new modules imported and its CLI reported MaskCode 0.8.0. The
disposable build workspace was removed and no dependencies were fetched.

### Real local detection in the coding loop

The optional installed-Codex fixture also passed with actual protected Qwen,
dummy credentials, and a local fixture provider. The agent read a file, applied
a patch, ran unittest successfully, and completed its final answer. Qwen detected
the unconfigured full person name in the read result; requests 2–4 contained its
issued placeholder and excluded the original. Exact name/email values were
preserved in the final file. All four requests forwarded without a gateway or
scanner block; one extraction repair succeeded. This cold run took **44.889 s**,
with 11 scanned chunks and 15 cache hits; the final scan took 2.637 s. Owned
processes and temporary state were cleaned up. No cloud inference was used.

### Live Astra coding task

The actual installed Codex, existing official authentication, protected local Qwen,
and `gpt-6-astra` at explicit `medium` effort completed a disposable synthetic
file-edit task. Codex exited 0; `greet()` was corrected; the synthetic contact
comment was preserved. Native JSON events confirmed execution of the exact
requested unittest command with exit 0 and an OK result, followed by a final
agent message. An independent test rerun passed too. All five
forwarded request bodies excluded the original email and exact project root.
There were zero local scan or gateway blocks; the last provider status was 200.

Total cold elapsed time was **66.299 s**. Local scanning accounted for 42.127 s,
with 13 newly scanned chunks and 22 cache hits across five requests. The final
scan took 2.570 s, reusing seven of nine chunks. No validation repair was needed
in this successful run. Owned client, gateway, and Ollama resources closed.
This confirms a live task, not universal task compatibility or confidentiality.
An earlier successful development run took 79.989 s. Cold loading varies, so
these runs are not a controlled speedup benchmark.

Earlier development probes did not complete: one failed before forwarding,
another edited the fixture but later stopped with an unclassified gateway error,
and a third stopped on a later local scan. The outside-home project-path gap
observed during those probes is now covered by automatic path registration and
regressions. All probes used synthetic data; no real confidential fixture was sent.

## 0.7.3 — Codex startup warning

MaskCode now suppresses Codex's generic unstable-feature banner for its own
launches. The intentional `skip_host_skill_discovery` restriction remains
enabled; the user's global Codex configuration is unchanged. This is a display
change and does not reduce cold model-loading time or change masking behavior.

- All 19 Codex client tests passed in 2.602 s with the installed-client opt-in,
  including local fixture-provider integration using synthetic credentials.
- No new cloud inference requests were made for this patch. Earlier live cloud
  evidence below remains specific to 0.7.0.

## 0.7.2 — local scan latency

Local-only probes on the same M1 Mac identified cold Qwen loading as the main
first-request delay. A fresh short-text scan took 47.909 s: Ollama reported
46.729 s loading, 0.890 s processing 331 prompt tokens (including the detector's
system prompt), and 0.190 s generating its result. An identical cached scan took
under 0.001 s; a separate warm short-text scan took 0.548 s. These are small
synthetic measurements, not end-to-end cloud latency promises.

Two owned-process diagnostic probes reported full Metal GPU offload, no CPU
fallback, and no permission or pipeline failures. In one, model weights were
ready by 1.045 s; Metal library setup took 4.778 s and construction of 422 kernel
pipelines took 19.471 s. Full local scan time was 26.344 s. These stages match
the [Ollama 0.11.10 Metal backend](https://github.com/ollama/ollama/blob/v0.11.10/ml/backend/ggml/ggml/src/ggml-metal/ggml-metal.m).
Diagnostic output stayed local to the disposable probes and was discarded.
No cloud requests or changes to other Ollama processes were made.

The patch keeps the owned model resident until the MaskCode session exits,
using Ollama's documented [negative keep_alive setting](https://docs.ollama.com/faq#how-do-i-keep-a-model-loaded-in-memory-or-make-it-unload-immediately).
It prevents an idle timeout from causing another cold load in the same session.
The first load in a new session remains expensive and retains model memory while
the session is open; shutdown still terminates the owned process.

The Codex adapter now omits only the exact registered public base instructions
from local AI extraction. The installed catalog supplies 21,261 characters;
both real installed-client authentication fixtures verify this exact match while
still scanning other request content. Deterministic masking always runs, and
modified instructions, wrong models, nested copies, later-discovered entities,
and explicit policy matches are covered by boundary regressions. Standalone
gateways have no exemption; registration is internal, bounded and launch-only.

Scan snapshots now include safe numeric duration and current-request progress.
The Claude interface shows completed/total chunks. Native Codex prints an initial
explanation and a numeric summary after exit; no output is injected over its
active terminal. Native reasoning-effort and service-tier choices are preserved.
Codex responses remain buffered before release for validation.

**373 tests ran in 35.143 s: 372 passed and one optional local-runtime test was
skipped.** Both installed-client opt-ins were enabled; actual local runtime
measurements are reported above. No new live cloud inference was used for this
patch. The separate exact-input cache remains session-local; this patch does not
claim to remove all repeated scanning when request structure changes.

## 0.7.1 — desktop Codex discovery

The launch failure reported from an ordinary terminal came from searching only
PATH. The development app supplied a PATH entry for its bundled Codex, hiding
that difference in the earlier check. Version 0.7.1 keeps PATH precedence and
also checks standard Codex.app and ChatGPT.app locations on macOS. Doctor uses
the same resolver and reports the selected executable.

- Full suite with installed-client opt-ins and Codex removed from PATH:
  **355 tests in 34.566 s, 354 passed and one optional local-runtime test skipped.**
  Installed Codex file/patch/test workflows used synthetic data and local fixture
  providers, finding the actual app-bundled executable through the fallback.
- Actual MaskCode launcher reached official Codex help with local Ollama and the
  normal sandbox active, while no Codex executable was visible on PATH: exit 0.
  No inference prompt was submitted. Temporary owned resources were cleaned up.
- Discovery tests cover PATH precedence, app paths containing spaces, missing or
  nonexecutable files, directories, broken symlinks and non-macOS behavior.
- An initial probe reordered PATH and selected a different installed Ollama;
  its local server timed out. The successful probe removed only app PATH entries
  and preserved the working Ollama selection. Other installed Ollama versions
  are not validated by this fix.

The earlier live cloud evidence below remains specific to 0.7.0; this patch did
not send new cloud inference requests or change the masking or transport rules.

## 0.7.0 validation

Validated on this Mac on 2026-09-13: Apple M1, 16 GiB RAM, Python 3.10,
Claude Code 2.1.247, Codex 0.153.4, Ollama 0.11.10, and the already installed
qwen2.5:1.5b model. Inference checks used synthetic contacts and disposable files.
No model download or sign-in change was performed.

### 0.7.0 check results

| Check | Result |
| --- | --- |
| Complete automated suite | **350 tests run in 33.835 s: 349 passed, one optional Ollama runtime test skipped.** Both installed-client opt-ins were enabled. Real Ollama was exercised separately in the local detector and live hybrid checks below. |
| Real local Ollama detector | A separately protected Ollama process detected unconfigured synthetic person and company names. Built-in email masking ran first. Stable placeholders replaced the names; a code change restored exact originals locally. No cloud inference was used for this check. |
| Local scan timing | The synthetic first scan took 26.18 s including cold model work. A scan of the resulting masked context took 0.6 s; its cached repeat took under 0.01 s. These are small-fixture measurements, not a general latency promise. Full agent instructions require more chunks. |
| Installed Claude coding loop with local detection attached | Actual MaskCode terminal and installed Claude completed Read → Edit → Bash unittest → final. Actual SemanticScanner used a fake local extraction model; provider responses were local fixtures. The company was absent from explicit policy and learned from the first prompt. Four requests excluded original company/email/path. Test failed before the edit and passed independently afterward; contacts and test source preserved. Edit/Bash keyboard approvals remained active; zero model-request approval dialogs or browser opens. |
| Installed Codex coding loop | Actual Codex completed file read → validated freeform apply_patch → unittest → final against a fake provider with dummy auth. Four requests concealed original email/path; local file values restored correctly. This verifies client/tool integration, not cloud model behavior. |
| Codex authentication transport | Fabricated local subscription-shaped credentials verified forwarding of Bearer/account headers through the actual installed CLI. No real credentials were read for this synthetic check. |
| Native Codex instruction preservation | Both API-key and fabricated subscription paths send the installed base instructions and retain all native input messages after legitimate masking. A regression fixes ordinary “basic instructions” being mistaken for Basic authentication. Real Basic credentials still mask; protected protocol keys block instead of being renamed. |
| Response negotiation | The gateway derives Accept from stream mode, matching the native client without forwarding arbitrary client header data. Exact JSON/SSE MIME types are compared case-insensitively. A missing MIME header is accepted only for an expected streamed Codex /responses reply that passes strict SSE framing, duplicate-free finite JSON, known event types and complete-response validation. HTML, lookalike types, failed/truncated streams and executable events after completion fail closed. |
| Actual terminal startup | MaskCode 0.7.0 banner, AI + MASKING, Ready, /privacy output and Ctrl+D exit 0 verified with the real installed engine and owned Ollama runtime. An initial raw-byte assertion missed Ready because terminal cursor reuse split the word; direct PTY interaction confirmed normal startup. No model request was sent. |
| Fable 5.1 live hybrid attempt | **Not passed.** The cloud provider returned HTTP 429 / rate_limit_error. The initial coding attempt reached its request bound before completing; a separate bounded diagnosis identified the status. Protected originals were absent from captured outgoing requests. This does not identify the exact account-limit cause. The launcher now sets documented CLAUDE_CODE_MAX_RETRIES=0. |
| Astra live hybrid round trip | **Passed.** Actual installed Codex, existing official authentication, local Qwen and gpt-6-astra completed one synthetic echo request: HTTP 200, exit 0, exact original email restored in final output. Email/home/temp originals were absent from the outgoing request; native instructions and streaming Accept were preserved. The provider omitted Content-Type; its 102,781-byte SSE reply passed strict validation and local restoration. Twelve local chunks, zero local/gateway blocks, no retry or timeout; 55.63 s cold. Owned resources closed. This verifies a live inference round trip; the file-edit/test loops above use fixture providers. |
| Local detector process boundary | External direct TCP/UDP blocked; loopback allowed for Ollama's runner; local weights reused read-only; temporary state removed on clean shutdown. Existing Ollama service untouched. Local/remote model checks reject cloud targets and missing weights rather than pulling or falling back. |
| Codex outer sandbox | Actual subprocess probes allowed project/additional-directory/private-temp/Codex-state writes, blocked outside writes and symlink/hardlink escapes, allowed outside reads, allowed gateway TCP, and denied other loopback/public sockets. Native inner sandbox is disabled solely to avoid macOS nested Seatbelt failure. |
| Termination cleanup | Subprocess tests run actual terminal-entry cleanup with an owned child. SIGTERM/SIGHUP stop that child, close state/engine/server, return 143/129, ignore repeated termination during cleanup, preserve SIGINT and restore caller handlers. SIGKILL/crashes cannot guarantee cleanup. |
| Detection and vault boundary | Malformed/hallucinated local results, scanner failure, sensitive typed numbers, invalid entities and stale approved previews block forwarding. Exact multilingual spans, embedded JSON, learned URL/base64 variants, cache behavior and bounded input tested. Auth never enters the local detector. |
| Protocol vocabulary and local AI | A real local scan exposed false positives on fixed words such as function and generated header values. These public lexemes/framing are excluded from semantic discovery; unknown names/content stay eligible. Regressions verify real names still mask and explicit policies are never bypassed by that exclusion. |
| Concurrent request discovery | A deterministic two-request regression proves header secret discovery cannot mutate the vault between another request's final validation and transmission. The regression fails with the earlier unlocked header checks. |
| Codex protocol | Namespace/function/custom patch history, complete and split-token SSE patches, done/completed copies and missing-name argument events tested. Malformed/injected patch framing and unsafe command restoration rejected. Client tracking metadata is dropped before discovery and forwarding. |
| Existing security and interaction behavior | Gateway routes/capabilities, credential pinning, parser ambiguity, review denial/expiry, incremental Claude text, truncated tool streams, bounded shell restoration, keyboard controls, draft/session recovery and official sign-in handoff retain regression coverage. |
| Packaging | A 0.7.0 wheel built offline without fetching dependencies; all new modules, the CLI entrypoint and complete license/review notices were present. Temporary build artifacts were removed. |
| Public source release | Default suite: 350 tests in 27.184 s, 343 passed and seven optional integration tests skipped. The release wheel includes MIT metadata, the complete original and third-party licenses, all modules and the CLI entrypoint. CI runs the default suite without provider accounts or model downloads. |

## Reproduce

```sh
MASKCODE_TEST_INSTALLED_ENGINE=1 MASKCODE_TEST_INSTALLED_CODEX=1 python3 -m unittest discover -s tests -q
MASKCODE_TEST_LOCAL_OLLAMA=1 python3 -m unittest discover -s tests -p 'test_ollama_runtime.py' -q
MASKCODE_TEST_LOCAL_OLLAMA=1 PYTHONPATH=tests python3 -m unittest test_codex_client.InstalledCodexLocalHybridTests -v
maskcode gateway doctor
```

Installed-client tests use temporary projects, dummy authentication and fake
provider transports. The local runtime opt-in uses existing Ollama weights and
never contacts a cloud model. Without their opt-in variables, those integration
tests skip. No request body, credential, or raw provider error is included in this
report.

An optional real Claude coding check uses existing official authentication:

```sh
MASKCODE_RUN_LIVE_AGENTIC=1 MASKCODE_LIVE_SEMANTIC=1 MASKCODE_LIVE_MODEL=claude-fable-5-1 python3 tests/live_agentic_smoke.py
```

It bounds requests, uses disposable synthetic files, permits only the test-specific
edits/commands, and independently checks the result. Provider rate limits can stop
it. It is not part of unittest discovery and does not change sign-in state.

## Earlier evidence and limits

The 0.6.0 Claude engine/gateway passed a real subscription coding task before the
local detector was added: four requests, edited implementation, independently
passing unittest, protected originals absent, and normal tool approvals. That
historical result is not a live Fable/Astra pass for 0.7.0. Earlier wheel/source
packaging checks retained complete third-party notices and the personal-use review;
the packaging configuration and dependency pins remain unchanged.

Detection is best effort. It can miss confidential meaning, indirect identifiers,
partial names and arbitrary encoding. Undetected content can be sent automatically;
use --mask-review for optional inspection. Reversible placeholders do not establish
legal anonymity, zero disclosure, or equivalent capability for every task.

Provider authentication still identifies the account. Originals can remain in
source files, official-client history, process memory, swap and crash dumps. The
macOS sandbox-exec mechanism is deprecated and is not a hardened boundary against
OS-helper IPC or hostile same-user software. It does not protect other sessions.
Codex reads outside the project remain available; its state/temp write exceptions
are explicit. Plugins, media, hosted tools and many executable substitutions remain
restricted. Codex display text streams; its tool calls and completion wait for
complete validation. Other OpenAI API streams remain buffered. Neither full feature parity nor a legal
certification is claimed; see LEGAL_REVIEW.md for the personal-use scope.
