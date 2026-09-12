# Security

MaskCode is experimental. Automatic detection can miss confidential information;
the cloud provider receives whatever remains after masking. Test with synthetic
data before considering any sensitive workload. See [README.md](README.md#privacy-boundary)
and [VALIDATION.md](VALIDATION.md) for the implemented boundary and its limits.

## Report a vulnerability

Use GitHub's **Security → Report a vulnerability** on this repository to report a
suspected leak, sandbox bypass, credential exposure, or unsafe tool restoration
privately. Please use synthetic reproductions and include the MaskCode version,
macOS version, relevant client versions, and minimal steps.

Do not include credentials, real confidential documents, account identifiers, or
unsanitized request/response logs in a public issue. If private reporting is
unavailable, open a minimal issue asking for a private reporting channel without
the vulnerability details or sensitive data.

The project has no guaranteed response time or security certification. Provider
client, Ollama, and model vulnerabilities may also require reporting upstream.
