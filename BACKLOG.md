# Backlog

Items that need a maintainer decision and were therefore not actioned
automatically.

## Resolve the `CONTRIBUTING.md` conflict in PR #18

**Status:** open — blocked on a content decision

PR #18 (`docs: add contributor setup, testing and private reporting guide`,
from `fatihcvs`) cannot be merged: `CONTRIBUTING.md` has a content conflict.
Both sides rewrote the file wholesale rather than editing it in place.

- `main` (`7c05b6b`) holds a concise guide written for this repository.
- The PR head (`e2fa53b`, "reconcile CONTRIBUTING.md with main and keep both
  guides") holds a longer guide with a development-setup section, a venv
  walkthrough, and a private vulnerability-reporting section.

The last commit on the branch shows the contributor already tried to reconcile
the two guides, so discarding their work outright would throw away a good-faith
effort. Keeping `main`'s version would drop the setup and reporting guidance.
Neither side is obviously correct, and the choice sets contributor policy for
the project, so it is a maintainer decision rather than an automatic fix.

**To unblock:** rebase the branch onto `main` and reconcile `CONTRIBUTING.md`
by hand, keeping both guides' unique sections under a single heading
structure.

### Note on CI for this PR

No check run was ever created for this PR. That is not a CI bug: the branch
predates `.github/workflows/ci.yml`, which was added to `main` in `a54c01c`
after the PR was opened. GitHub cannot evaluate a workflow file that does not
exist on the merge ref, and the merge ref cannot be rebuilt while the conflict
stands. Once the conflict is resolved and the branch is rebased, CI will run
normally.