<!-- SPDX-License-Identifier: Apache-2.0 -->

# Required Repository Settings

These controls cannot be enforced solely by files in this repository. A repository administrator must configure and periodically verify them in GitHub.

## Contributions

- Enable **Require contributors to sign off on web-based commits**.
- Require pull requests before merging to `main`.
- Install the Linux Foundation DCO GitHub App if desired in addition to the repository's `DCO sign-off` workflow.
- Require these status checks on `main`:
  - `DCO sign-off`;
  - `rust`;
  - `audit`;
  - `cargo-deny`.
- Require one approval, dismiss stale approvals, require approval of the latest push, and require conversation resolution.
- Block force pushes and deletion of `main`; apply rules to administrators where practical.

## Merge policy

- Enable squash merging.
- Disable merge commits.
- Rebase merging is optional.
- Ensure every contributing commit passes DCO before merge; a squash commit does not cure unsigned contribution commits.
- Automatically delete merged head branches.

## Security

Enable private vulnerability reporting, Dependabot alerts and security updates, secret scanning, push protection, and dependency review where available.

## Validation

Open a temporary pull request containing an unsigned commit and confirm `DCO sign-off` fails and branch protection blocks merge. Amend it with `git commit --amend --signoff --no-edit`, force-push with lease, and confirm the check passes.
