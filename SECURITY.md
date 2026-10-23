<!--
SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and gose Authors
SPDX-License-Identifier: MIT
-->

# Security Policy

gose is JOSE/JWT/JWK/JWS/JWKS implemented in Go: it parses and verifies untrusted tokens, and
signs and encrypts with key material the caller supplies. A defect here can mean a signature that
verifies when it should not, a token that is accepted past its expiry, or a key that leaks. We take
reports seriously and would rather hear about a suspected issue than not.

This project is an Eclipse Foundation project and adheres to the
[Eclipse Foundation Vulnerability Reporting Policy](https://www.eclipse.org/security/policy/).

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull
requests.**

Report privately through any of these channels:

- **[GitHub private vulnerability reporting](https://github.com/eclipse-keypont/gose/security/advisories/new)**
  — preferred. It keeps the report, the fix and the advisory in one place.
- **The Eclipse Foundation Vulnerability Reporting Tracker**, by creating a
  [confidential issue](https://gitlab.eclipse.org/security/vulnerability-reports/-/issues/new?issuable_template=new_vulnerability).
  This is the Foundation-level channel and the right one if the issue spans several Eclipse KeyPont
  projects.
- **The Eclipse Foundation security team**, at <security@eclipse-foundation.org>. See the
  [Eclipse Foundation Security Policy](https://www.eclipse.org/security/policy/) for the
  Foundation-level process. Use this channel if you would rather not report through GitHub or GitLab.

### What to include

The more of this you can supply, the faster we can confirm and fix:

- A description of the issue and why you believe it has security impact, including the type of
  issue (for example a signature that verifies incorrectly, an algorithm confusion, or a secret
  leak).
- The affected version or commit, and whether `master` is affected.
- The JOSE object involved (JWS, JWE, JWK, JWKS or JWT) and the algorithm or key type, if the issue
  depends on one.
- Step-by-step instructions to reproduce the issue, and the location of the affected source code
  (tag/branch/commit or direct URL), with full paths of the source files involved.
- Any configuration required to reproduce the issue, and related log files if you have them.
- A minimal reproducer — a token, a key set or a short Go snippet that triggers the bug is often
  the clearest one. Proof-of-concept or exploit code is welcome if you have it.
- Whether you intend to disclose publicly, and on what timeline.

Reports in any language are fine, and a partial report is better than none.

## What to expect

We will tell you when we have confirmed the issue, when a fix lands, and when the advisory is
published. If we conclude the report is not a vulnerability we will explain why, and you are
welcome to push back. This is a modest project; we do our best to respond promptly.

We work on a best-effort basis, but a strong security CI/CD pipeline backs every change: linting,
static analysis, vulnerability scanning and signed, provenance-attested releases. It reduces the
odds of a defect reaching a release, and it is why we would rather hear about a suspected issue
than not.

## Disclosure

We follow coordinated disclosure. We ask that you give us a reasonable opportunity to release a fix
before disclosing publicly — as a default, 90 days from acknowledgement, or until a fix is
released, whichever comes first. When a fix is released we publish a
[GitHub Security Advisory](https://github.com/eclipse-keypont/gose/security/advisories),
with a CVE where one is warranted; for Eclipse projects CVEs are assigned through the Eclipse
Foundation security team. Reporters are credited by name unless they ask not to be.

## Supported versions

| Version  | Supported                        |
|----------|----------------------------------|
| `v1.x`   | Yes — active development         |
| `v0.x`   | No — upgrade to `v1.x`           |

Fixes land on `master` first and ship in the next tagged release.

## Scope

**In scope** — anything in this repository that could let a token be accepted when it should not,
or leak key material, including:

- Signature or MAC verification that succeeds for the wrong key, the wrong algorithm, or a
  tampered payload — including algorithm confusion and `alg: none` handling.
- Claim validation that can be bypassed: `exp`, `nbf`, `iat`, `aud`, `iss` or `typ` checks that do
  not hold where they are documented to.
- Key material, private keys or shared secrets leaking through logs, error messages, returned
  buffers or memory that is not cleared.
- Parsing of untrusted JOSE input that is unsafe: unbounded allocation, panics on malformed input,
  or a header/parameter that silently changes the operation performed.
- Encryption (JWE) that is malleable, or that accepts a content-encryption or key-wrapping
  algorithm the caller did not ask for.
- Supply-chain integrity of the release pipeline: the signed tags, SBOM and SLSA provenance.

**Out of scope:**

- Vulnerabilities in a dependency, unless gose's use of the dependency is what makes them
  exploitable. Report those upstream; `govulncheck` and Dependabot cover us for the rest.
- Insecure use by the caller — for example verifying a token without checking the issuer or
  audience, or accepting a key from an untrusted source. If our documentation encourages an
  insecure pattern, that *is* worth reporting.
- Test-only code and the throwaway keys used by the test suites.

## Verifying what you run

Every tagged release ships a signed source archive, a keyless cosign signature and SLSA3 build
provenance. If you need to confirm that the source you are running is what we published, see
[Releases & verification](./README.md#releases--verification) in the README.

## Security posture

Every push and pull request runs golangci-lint, `go vet`, govulncheck, gosec, CodeQL, native GitHub
secret scanning, dependency review and an
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/eclipse-keypont/gose)
evaluation. These reduce the odds of a defect reaching a release; they do not replace your report.
