# CLAUDE.md - cryptos-node

Working agreement for this repository. It was scaffolded from `Bugs5382/project-template`;
the governance below is shared across all repos created that way.

## Enforced by hooks (run `bash .claude/hooks/install.sh` once per clone)

- Conventional Commits on commits, issue titles, and PR titles.
- No AI tells in commits/issues/PRs/comments/source; no emoji in source or commit messages (emoji
  are allowed in Markdown docs and CI workflow files).
- Pre-push: the ecosystem's format/lint/test gate must pass (Go: gofmt/vet/golangci-lint/test;
  npm: lint/test scripts; Python: ruff/pytest).

## Conventions

- Branching: never commit to `main`. Work on a feature/working branch; open a PR.
- Commits: Conventional Commits (`type(scope): description`). The operator (@CryptOS-PKI) is the
  author of record on every commit.
- Voice: human-authored. No attribution trailers (`Co-Authored-By`, `Generated with`), no robot
  glyphs/emoji, no session framing.
- Local design notes live in a non-tracked `plan/` folder; delete a note when its work is done.
- GitHub Actions: a job id must be a plain identifier (a letter or `_`, then alphanumerics/`-`/`_`);
  put emoji and display text in the job's `name:`, never the job key. The Actionlint check
  (`.github/workflows/action-lint.yaml`) enforces this, so a malformed workflow fails at PR time
  instead of silently at startup on `main`.

## Engineering discipline

- Root-cause before fixing: confirm the actual cause with evidence before changing code; do not
  patch symptoms.
- Map every reference before removing a feature: trace its wiring across the tree first, preserve
  adjacent behavior that only looks related, and defer-and-flag an entangled piece rather than
  guessing it.
- Verify with evidence, not assertions: run the real check for what changed (lint, a full
  template/build render, `actionlint` for workflows) before calling it done. Green CI is necessary,
  not sufficient.
- One concern per branch/PR, even tiny ones — it keeps reviews and the draft release notes clean.
- When PRs interact, state an explicit merge ORDER rather than opening them and walking away:
  anything a *tag* triggers needs its inputs on `main` first; a new *gate* (check) needs the
  violations it catches fixed first; a workflow that builds from committed content needs that
  content merged first.
- Semver framing: `breaking` only means breaking against a *released* version; removing something
  that was never shipped is not a breaking change.
- Cross-repo reconciliation goes through a neutral drop-zone outside both repos — never a repo
  inside a repo, and no accidental gitlinks/submodules.

## Workflow

Issue (from a template; free-form issues are disabled) -> for sequential / multi-step work, a parent
issue with ordered **sub-issues** -> put it on the active **milestone** -> branch
`<type>/<issue#>-<slug>` -> code (comments cite the issue) -> PR with a Conventional Commit title
(the autolabeler sets the category label from the title), the template body, and a **closing
summary** before merge -> **squash** merge. The operator (@CryptOS-PKI) is the assignee.

On merge, release-drafter drafts the next notes by label -- **nothing tags automatically**. When
the first push to main resolves the version, rename the milestone to that version. The maintainer
then **manually publishes the GitHub Release**, which creates the tag with the drafted notes (and
triggers the publish where the repo ships a package).

Keep public artifacts (issues, PRs, commit messages) free of references to local-only design notes.

## Releasing

On every push to `main` the **Release Drafter** workflow (`.github/workflows/release-drafter.yml`)
drafts the next release notes using the built-in `GITHUB_TOKEN`. **Nothing tags automatically.**
The maintainer then publishes the GitHub Release by hand, which creates the `vX.Y.Z` tag with the
drafted notes and triggers the publish workflow where the repo ships a package.

**GitHub Action repos release differently** — a composite/JS action has no package manifest and is
**not** published to a registry. The maintainer manually tags `vX.Y.Z`, publishes the GitHub
Release, and repoints the floating major tag `@vN` (e.g. `git tag -fa v1 -m "v1 -> v1.2.3" v1.2.3 &&
git push origin v1 --force`) so consumers pinned to `owner/repo@vN` pick up the release; publishing
to the GitHub Marketplace is an optional manual step. The **first release is `v1.0.0` by hand** —
release-drafter would otherwise draft `v0.1.0` on the first run. See `ecosystems/action/README.md`
for the full action-release sequence.

### Docs site and first-release gotchas

- A tag-gated GitHub Pages deploy (publishing only on `vX.Y.Z`) fails at the Deploy step unless the
  auto-created `github-pages` environment allows tag refs. Once, alongside enabling Pages
  (Settings -> Pages -> Source = GitHub Actions), add a tag policy, then re-run the failed Deploy
  job (no need to re-cut the tag):
  `gh api -X POST repos/CryptOS-PKI/cryptos-node/environments/github-pages/deployment-branch-policies -f name='v*' -f type=tag`
- Docusaurus MDX 3: avoid the `## Heading {#custom-id}` explicit-id syntax (it fails to compile);
  rely on the auto-generated slugs.
