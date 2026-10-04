# Contributing to A2A Drift

Thanks for your interest in this project, and for helping improve agent-card
validation and endpoint probing. Keep changes focused, describe the behavior you
are changing, and include a regression test for a bug fix.

## Development setup

You need Git and Python 3.9 or newer, as declared in `pyproject.toml`.

1. Fork the repository on GitHub, then clone your fork:

   ```sh
   git clone https://github.com/YOUR-USERNAME/a2a-drift.git
   cd a2a-drift
   ```

   Replace `YOUR-USERNAME` with your GitHub username.

2. Create a branch for your work, for example `git switch -c fix/retry-behavior`
   or `git checkout -b my-feature`.

3. From the repository root, create an isolated environment:

   ```sh
   python -m venv .venv
   ```

   If your system calls Python 3 `python3`, use that command to create the
   environment.

Activate it on macOS/Linux:

```sh
source .venv/bin/activate
```

Or in Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use `.\.venv\Scripts\python.exe` instead of
`python` in the remaining commands; changing the execution policy is unnecessary.

Install the editable package and its development tools:

```sh
python -m pip install -e ".[dev]"
python -m a2a_drift.cli --help
```

The `dev` extra installs the same tools CI runs: `pytest`, `pytest-cov`, `ruff`
and `mypy`. `python -m a2a_drift.cli` runs the CLI module from this checkout
without relying on an installed console script.

## Tests

Make sure tests pass locally before opening a pull request. Run from the
repository root:

```sh
python -m pytest -q
python -m pytest -q --cov=a2a_drift --cov-report=term-missing
```

Tests live in `tests/`; shared fixtures are in `tests/conftest.py`. To narrow a
run:

```sh
python -m pytest -q tests/test_retry.py
python -m pytest -q -m unit
```

Mark isolated unit tests `unit`. Reserve `slow` for tests that genuinely make real
network calls; none exist yet. Mixed test modules may remain unmarked.

The existing tests mock HTTP requests; you do not need a live agent, credentials,
or a public endpoint. Follow this pattern for new tests, and mock backoff sleeps
when testing retries. Test the failing case before fixing a bug, then run the
whole suite. Coverage output helps identify untested branches, and a coverage
floor is enforced: `pyproject.toml` sets `fail_under = 100` under
`[tool.coverage.report]`, so a run below full coverage exits non-zero. Cover new
code with a test rather than lowering the number or excluding the file.

Only probe endpoints you own or have permission to test. Do not put real tokens,
private agent cards, or customer responses in fixtures or issue reports.

## Code style

Follow the existing code style, and run the project's linters and formatters if
it has them. Use four-space indentation and descriptive names, and keep Python 3.9
compatibility. For Python changes, inspect Ruff's diagnostics and formatting
suggestions:

```sh
python -m ruff check .
python -m ruff format --check .
```

CI runs pytest on Python 3.10–3.12 and `ruff check --isolated --select E,F,I .`.
No project-specific Ruff configuration is defined; the local commands above use
Ruff's defaults and may report existing issues. Distinguish those from your
changes. Avoid reformatting unrelated files or adding broad suppressions just to
make a local check pass. Record any remaining failures in the PR.

## Issues and pull requests

### Reporting issues

Before opening an issue, check existing issues and PRs to avoid duplicating work.
For a larger feature, explain the proposed behavior in an issue before implementing
it. When reporting a problem, open an issue at
[GitHub Issues](https://github.com/yunaremaia/a2a-drift/issues) with:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, version)

### Submitting pull requests

1. Make a focused change, add tests where appropriate, and update usage examples
   if behavior changes.
2. Run the tests and checks above. Review `git diff --check` and your diff before
   committing; generated reports and environment files should stay out of the PR.
3. Use a short, descriptive commit message. Existing history uses prefixes such
   as `fix:` and `feat:`; `docs:` and `test:` also describe focused contributions.
4. Open a PR against this repository's default branch, with a clear description of
   the changes. Link or reference any related issue numbers, describe the
   before/after behavior, and list the exact checks and Python version used,
   including failures or checks you could not run.

Review may request changes to behavior, tests, documentation, or scope. Keep
follow-up changes in the same PR and explain how you addressed the feedback.
Maintainer availability varies; there is no guaranteed review turnaround.

## Code of Conduct

Be respectful and constructive. Reviews are about the code, not the person who
wrote it.

## Private security reports

Do not publish an exploitable vulnerability, sensitive endpoint, or credentials
in a public issue or PR. See
[SECURITY.md](https://github.com/yunaremaia/a2a-drift/blob/main/SECURITY.md) for
the policy. Contact the package maintainer privately at
[yunare@gmail.com](mailto:yunare@gmail.com), the author address listed in
`pyproject.toml`, with the subject `a2a-drift security report`.

Include the affected version or commit, expected and actual behavior, potential
impact, and a minimal reproduction using synthetic data and an authorized local
endpoint. Redact secrets. Coordinate a fix and public disclosure with the
maintainer before sharing exploit details.
