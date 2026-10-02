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

## Consider making `--allow-internal` and `--deny-internal` mutually exclusive

**Status:** open — needs a maintainer decision on CLI semantics

Today the two flags are independent `store_true` booleans and the effective
value is `args.allow_internal or not args.deny_internal`. Passing **both** flags
therefore resolves to "allow internal", i.e. the more permissive of the two
wins, with no warning:

```sh
a2a-drift check http://127.0.0.1:8080/card.json --deny-internal --allow-internal
```

This is intentional in the sense that it is what the current code does, and it
is pinned by `test_allow_internal_wins_when_both_flags_are_passed` in
`tests/test_cli.py`. It is listed here because the interaction is surprising
enough to deserve an explicit decision. The safe options are:

- Put both flags in a mutually exclusive `add_mutually_exclusive_group`, which
  makes `--deny-internal --allow-internal` an argparse error (exit 2) and
  removes the ambiguity entirely.
- Keep the current behaviour but document it in `--help`.

Note the ordering above matters for review: whichever way this goes, the security
meaning of `--deny-internal` (CWE-918) should not depend on flag order. This was
left unchanged here because picking a CLI contract is a product decision, not a
bug fix.