# MaskCode licensing and provider-use notes

## Open-source release — 2026-09-13

MaskCode's original source and documentation are released under the
[MIT License](LICENSE). This permits use, modification and redistribution under
that license; the source license is not restricted to personal use. Retained
third-party notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The published repository contains MaskCode's gateway, terminal, adapters, tests
and documentation. It does not bundle Claude Code, Codex, Ollama, model weights,
provider credentials or an account-access service. Users install and authenticate
their own clients and remain responsible for the terms of the services they use.
MIT licensing of this code does not grant provider access, subscription resale,
trademark rights, or permission to disclose someone else's confidential data.

The provider review below describes the original personal, user-operated setup;
it is not a certification of every deployment made from this public source.
Hosting an account-backed service for other people has different requirements
and needs its own assessment. No provider endorsement or trademark clearance is
claimed for this release.

## Original review scope

Reviewed on 2026-09-12 for version 0.5.1. Scope confirmed by the user: one person,
on their own Mac, using their own provider account. This records implementation
decisions and current public guidance. It is not a legal opinion, provider
approval, or a guarantee of compliance in every jurisdiction.

Version 0.7.0 adds an installed Ollama model as a local span detector and extends
the installed Codex adapter. Model weights and provider binaries are not bundled.
The default detector uses existing local weights; it does not make the cloud
reasoning model local. MaskCode does not extract stored credentials, implement its
own subscription login, or turn subscriptions into API credits. The provider
review below remains dated 2026-09-12; this implementation addendum is dated
2026-09-13. Technical verification is recorded separately in VALIDATION.md.

Version 0.6.0 changes the normal coding launcher to automatic background masking,
as requested by the user. Per-request review is now optional (`--mask-review`);
normal tool permissions remain active. This changes the exposure tradeoff:
unrecognized confidential content can leave without an individual request review.
It does not change the provider, licensing, or personal-use scope below.

## Provider access

**Claude personal account.** Anthropic documents a local gateway configured with
`ANTHROPIC_BASE_URL` that preserves a saved Claude subscription login and forwards
the required OAuth capability. MaskCode uses that mechanism with the separately
installed, unchanged Claude Code executable. Sign-in happens through the official
client. MaskCode has no login service, account pool, credential export, or usage
resale. The inference gateway necessarily handles the account's authentication
headers transiently in local memory; it does not read credential stores or write
credential logs. [Gateway guidance](https://code.claude.com/docs/en/llm-gateway#subscriptions-and-gateways).

Anthropic's June 16 update says the planned SDK billing change was paused and
that SDK, `claude -p`, and third-party app usage still uses subscription limits.
The older monthly-credit material below that update is expressly historical.
This does not guarantee a plan will retain those terms in future.
[Billing update](https://support.claude.com/en/articles/15036540-use-the-claude-agent-sdk-with-your-claude-plan).

The legal guidance distinguishes end users running the unmodified client with
their own credentials from developers offering their own subscription login or
intermediating usage for other people. It also describes conditions for running
the client in a product. Our interpretation is that this personal, user-operated
tool follows the documented local-gateway pattern; Anthropic has not specifically
approved MaskCode. Its applicable terms and usage policies continue to govern
the account. Distribution or hosting for other users needs a separate assessment;
do not treat this review as permission to offer a subscription-backed service.
[Provider legal guidance](https://code.claude.com/docs/en/legal-and-compliance).

**Claude API.** A user's own API key can be supplied through the official client,
with separate API billing. MaskCode does not create credits or hide that billing.
For an independently offered developer application, the documented starting point
is API-key authentication; this build does not implement Bedrock, Google Cloud,
or Foundry adapters. [Agent SDK guidance](https://code.claude.com/docs/en/agent-sdk/overview).

**OpenAI and Codex.** OpenAI documents `requires_openai_auth = true` for a custom
LLM proxy using ChatGPT or API-key authentication. The Codex adapter uses the
official client and that setting. Its per-launch model catalog selects standard
Responses with local function/patch tools, preserving the installed catalog's
model identity and instructions. It changes neither the vendor binary nor saved
user configuration. The MaskCode interface uses Claude; the Codex path uses the
native Codex interface. Model access and quota remain provider-controlled. The
standalone OpenAI API gateway is distinct from a ChatGPT subscription.
[OpenAI authentication guidance](https://learn.chatgpt.com/docs/auth#alternative-model-providers).

## Branding and source licenses

- The application is named MaskCode and labels its agent **Powered by Claude**.
  It does not use Claude-branded ASCII art or present itself as an Anthropic
  product. Factual documentation identifies the installed Claude Code executable.
  [Agent branding guidance](https://code.claude.com/docs/en/agent-sdk/overview#branding-guidelines).
- The Hermes-inspired layout is independently implemented. No Hermes runtime,
  wordmark, caduceus, logo asset, or source module is bundled. Hermes is credited
  as a design reference, without an endorsement claim.
- The audited dependency versions are prompt_toolkit 3.0.52 and wcwidth 0.7.0.
  Their full notices, relevant Unicode data notice, and Hermes acknowledgement
  are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), included in installable
  distributions. Review dependency and notice changes together when upgrading.
- Ollama and its model weights are separately installed components. This build
  reuses an existing local model and distributes neither the runtime nor weights.
  Their licenses apply independently; a future installer or redistribution must
  review the exact runtime and model artifacts it includes.
- MaskCode's original code is licensed under MIT as of the source release above.
  Third-party components retain their own notices and licenses. No ownership or
  trademark registration is established by this document.
- **MaskCode has not undergone trademark clearance.** An unrelated
  [existing software project](https://github.com/craiglagegit/MaskCode) already uses
  the name. That does not establish infringement, but no exclusivity or
  name-availability claim is made. Jurisdiction-specific trademark clearance has
  not been performed, and the MIT license does not grant trademark rights.

## Technical controls and their limits

The gateway binds to loopback, requires random capabilities, keeps maps in memory,
and does not log request bodies or credentials. The normal coding launcher uses
automatic masking; `--mask-review` enables request inspection. The standalone
`gateway serve` inspector still defaults to review. The launcher
checks its direct-socket restriction and preserves the official executable.
Required authentication/version/capability headers pass through unchanged, or the
request is blocked; no substitute credential or fabricated capability is created.
Because masking can reshape system content, the launcher sets the documented
`CLAUDE_CODE_ATTRIBUTION_HEADER=0` option at the client. The binary is not patched.
[Gateway compatibility guidance](https://code.claude.com/docs/en/llm-gateway-protocol).

The local detector sees source fragments after known-rule masking and never sees
authentication headers. It can add exact detected spans to the memory-only map,
but cannot rewrite source, choose a remote destination, or waive a failed check.
Invalid output and runtime failures block forwarding. Its isolated process blocks
external direct sockets but permits loopback for the local runner; this does not
establish isolation from OS-helper IPC or hostile software on the same Mac.

These controls are not a compliance certification. Masking is reversible,
can miss confidential meaning, and can restrict client features. The provider
still receives account authentication and the forwarded content. The official
client can retain original data in local session files. No claim of legally
anonymous data, zero disclosure, privilege preservation, or sector-specific
compliance is made. See [VALIDATION.md](VALIDATION.md) for tested boundaries.

Personal use does not establish permission to disclose an employer's, client's,
or another person's information. The applicable contract, data permissions,
provider settings and law must allow the actual upload; masking alone cannot
decide that. Jurisdiction, dataset obligations and contractual permissions were
not supplied or independently reviewed. This tool is not approved for a hosted
service or a public product by this assessment.
The provider's [consumer terms](https://www.anthropic.com/legal/consumer-terms)
or [commercial terms](https://www.anthropic.com/legal/commercial-terms) remain
applicable; MaskCode does not replace them.
