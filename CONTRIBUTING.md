# Contributing to MaskCode

MaskCode is experimental. Useful contributions include reproducible privacy
failures, protocol compatibility fixes, clearer terminal interactions, and tests
that exercise real behavior. Keep changes focused and preserve the documented
limits: detection is best effort, provider access belongs to the user, and the
Claude and Codex interfaces currently differ.

## Development setup

Use macOS with Python 3.10 or newer. From a clone of this repository:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -q
```

The default suite uses synthetic fixtures and local test servers. Some tests
exercise macOS sandbox restrictions; installed-client and local-model tests are
optional. No real cloud inference is required for the default suite.

To exercise an installed official Claude Code or Codex binary with temporary
projects, fabricated credentials, and local fixture providers:

```sh
MASKCODE_TEST_INSTALLED_ENGINE=1 MASKCODE_TEST_INSTALLED_CODEX=1 python -m unittest discover -s tests -q
```

To exercise the real local detector, first install Ollama and explicitly download
the weights as described in the [quickstart](README.md#quickstart), then run:

```sh
MASKCODE_TEST_LOCAL_OLLAMA=1 python -m unittest discover -s tests -p 'test_ollama_runtime.py' -q
```

This opt-in uses local weights; it does not download them or call a cloud model.
Live provider checks are separate and use the runner's own authentication and
usage allowance. Do not add them to ordinary test discovery or run them without
explicit intent. [VALIDATION.md](VALIDATION.md) distinguishes fixture-backed
integration evidence from live provider results.

## Changes and pull requests

- Explain the concrete problem, resulting behavior, and how you verified it.
- Add a focused regression for changes to detection, restoration, request
  validation, credentials, isolation, or approval behavior. Use synthetic values
  such as `person@example.com` and disposable temporary directories.
- Preserve fail-closed behavior. Do not solve compatibility problems by silently
  bypassing masking, weakening approval checks, or forwarding unknown transports.
- Keep model downloads, vendor binaries, credentials, private policy files,
  generated logs, and local session history out of commits.
- Update documentation when behavior or limitations change. Keep live-provider
  claims specific to the actual model, test, and result.

Run the relevant tests while developing and the default suite before submitting.
Include any optional checks you ran, along with the installed client version;
state skipped or unavailable checks plainly.

## Bug reports and privacy

Provide the MaskCode version, macOS/Python version, selected backend and client
version, a minimal synthetic reproduction, and expected versus actual behavior.
Replace personal paths and account details with examples. Never attach real
credentials, customer files, private policies, raw request bodies, or unredacted
terminal/session logs to an issue or pull request.

For a privacy failure, reproduce it with invented data first. If a report cannot
be shared safely, use GitHub's private vulnerability reporting when available;
otherwise ask for a private reporting channel without publishing sensitive details.

MaskCode source contributions use the repository's [MIT License](LICENSE).
Retain applicable attribution and license notices when introducing third-party
material. Vendor clients and model weights are not part of this source license.
