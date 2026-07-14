<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to PepperMesh

Thank you for contributing to PepperMesh.

PepperMesh is licensed under the Apache License, Version 2.0. We accept contributions under the Developer Certificate of Origin, Version 1.1.

## Code of Conduct

Participation in the PepperMesh project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before You Begin

For significant changes, please open an issue or discussion before starting implementation. This helps ensure that the proposed work fits the project's architecture and roadmap.

Examples of significant changes include:

- new network protocols;
- changes to persistent storage formats;
- changes to block addressing or replication;
- changes to node identity or trust;
- new compute sandbox mechanisms;
- compatibility-breaking API changes;
- major new dependencies.

Small bug fixes, documentation corrections, and focused tests generally do not require prior discussion.

## Developer Certificate of Origin

PepperMesh uses the Developer Certificate of Origin, Version 1.1. The DCO is a certification by you that you have the right to submit your contribution under the project's open-source license. The complete text is in [DCO](DCO).

Every commit containing a contribution must include a `Signed-off-by` line using your real name and an email address that identifies you:

```text
Signed-off-by: Your Name <you@example.com>
```

Add it automatically with:

```bash
git commit -s -m "Describe the contribution"
```

The sign-off is required on every contributing commit, not merely in the pull request description. By adding it, you certify that your contribution complies with the DCO.

## Configure Git Identity

```bash
git config user.name "Your Name"
git config user.email "you@example.com"
```

Use `--global` to configure these values globally. Use an identity you are authorized to use; your sign-off name should normally be your real name rather than a username or organization name.

## Fix Missing Sign-Offs

For the latest commit:

```bash
git commit --amend --signoff --no-edit
git push --force-with-lease
```

For several commits relative to `main`:

```bash
git fetch origin
git rebase --signoff origin/main
git push --force-with-lease
```

Review the rewritten history with `git log --format=full`. Never add another contributor's sign-off on their behalf.

## Sign-Off Is Not Cryptographic Signing

The DCO sign-off added by `git commit -s` is a textual commit-message trailer. It is different from cryptographically signing a commit with `git commit -S`. Cryptographic signing does not replace DCO sign-off. To use both:

```bash
git commit -s -S -m "Describe the contribution"
```

## Pull Request Requirements

A pull request should:

- explain the problem and approach;
- include appropriate tests;
- update documentation when behavior changes;
- keep unrelated changes separate;
- pass formatting, linting, tests, license, security, and DCO checks;
- identify third-party material and avoid incompatible licenses;
- include sign-offs on all contributing commits.

By submitting a pull request, you agree that your contribution will be distributed under the repository's Apache License 2.0 terms.

## Generated and AI-Assisted Contributions

You are responsible for ensuring that everything you submit can legally be contributed to PepperMesh. Review generated or AI-assisted material and ensure you have the right to distribute it under Apache-2.0.

Do not submit:

- code copied from incompatible open-source projects;
- code copied from proprietary repositories;
- confidential employer material;
- output that substantially reproduces third-party copyrighted code;
- material subject to terms that prohibit open-source distribution.

Disclose substantial generated or AI-assisted code in the pull request when that helps reviewers evaluate provenance, correctness, or security.

## Third-Party Code and Dependencies

Do not copy third-party material into the repository without identifying its source, copyright holder, license, modifications, and required attribution or notice.

New dependencies must have licenses compatible with Apache-2.0 and PepperMesh's distribution model. Unusual, source-available, noncommercial, field-of-use-restricted, strong-copyleft, or unknown licenses require maintainer review.

## Security Issues

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).

## Review and Acceptance

Maintainers may decline a contribution for technical, architectural, security, maintenance, licensing, or project-direction reasons. Acceptance does not create an employment, partnership, support, or compensation relationship.
