# Contributing to cryptos

This repository follows the Bugs5382 standard workflow.

## Workflow

1. Open an issue from a template (free-form issues are disabled). For multi-step work,
   use a parent issue with ordered sub-issues, and put it on the active milestone.
2. Branch from `main` as `<type>/<issue#>-<slug>` (for example `feat/12-add-listener`).
3. Commit using Conventional Commits (`type(scope): description`) and sign off every
   commit with `git commit -s` (see [Developer Certificate of Origin](#developer-certificate-of-origin)).
   The sign-off is the only trailer: no attribution trailers, and no emoji in source or
   commit messages (emoji are fine in Markdown).
4. Open a PR with a Conventional Commit title. The autolabeler sets the category label
   from the title; fill the PR template, reference the issue (`Closes #N`), and add a
   closing summary before merge.
5. PRs merge by squash. On merge, release-drafter drafts the next release notes; the
   maintainer publishes releases manually.

Keep one concern per PR, even small ones. When editing GitHub Actions workflows, a job id must be a
plain identifier (a letter or `_`, then alphanumerics/`-`/`_`); put emoji and display text in the
job's `name:`. The Actionlint check enforces this.

## Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) 1.1. Signing off a commit certifies that you wrote the change, or otherwise have the
right to submit it under this repository's licence (Apache License 2.0), and that the
contribution and your sign-off are public and kept permanently. The organization's
[contributing guide](https://github.com/CryptOS-PKI/.github/blob/main/CONTRIBUTING.md#developer-certificate-of-origin)
quotes the full certificate.

Sign off with `git commit -s`. Git builds the trailer from your `user.name` and
`user.email`, and it has to match the commit's author:

```text
Signed-off-by: Jane Doe <jane@example.com>
```

The DCO check fails a pull request when any commit, other than a merge commit, has no
matching sign-off. To sign off commits you have already pushed, run
`git rebase --signoff origin/main` and force-push the branch.

## Local setup

Install the governance hooks once per clone: `bash .claude/hooks/install.sh`. They
enforce Conventional Commits and the no-tell/no-emoji rules before you push; CI enforces
the same. See `CLAUDE.md` for the full working agreement.
