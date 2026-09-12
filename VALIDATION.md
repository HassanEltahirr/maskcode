# MaskCode validation

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

## Current evidence

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
restricted. OpenAI responses are buffered. Neither full feature parity nor a legal
certification is claimed; see LEGAL_REVIEW.md for the personal-use scope.
