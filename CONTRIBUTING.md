# Contributing to A2A Drift

Thanks for helping improve agent-card validation and endpoint probing. Keep
changes focused, describe the behavior you are changing, and include a regression
test for a bug fix.

## Development setup

You need Git and Python 3.9 or newer, as declared in `pyproject.toml`. Fork the
repository on GitHub, then clone your fork. From the repository root, create an
isolated environment:

```sh
git clone https://github.com/YOUR-USERNAME/a2a-drift.git
cd a2a-drift
python -m venv .venv
```

Replace `YOUR-USERNAME` with your GitHub username. If your system calls Python 3
`python3`, use that command to create the environment.

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

Install the editable package and development tools:

```sh
python -m pip install -e . pytest pytest-cov ruff
python cli.py --help
```

Development tools are installed explicitly because the project does not currently
define a development dependency extra. `python cli.py` runs the CLI from this
checkout without relying on an installed console script.

## Tests

Run from the repository root:

```sh
python -m pytest -q
python -m pytest -q --cov=a2a_drift --cov-report=term-missing
```

Tests currently live in `test_a2a_drift.py` and `test_retry.py`. To narrow a run:

```sh
python -m pytest -q test_retry.py
```

The existing tests mock HTTP requests; you do not need a live agent, credentials,
or a public endpoint. Follow this pattern for new tests, and mock backoff sleeps
when testing retries. Test the failing case before fixing a bug, then run the
whole suite. Coverage output helps identify untested branches; no coverage
threshold is configured yet.

Only probe endpoints you own or have permission to test. Do not put real tokens,
private agent cards, or customer responses in fixtures or issue reports.

## Code style

Use four-space indentation and descriptive names, and keep Python 3.9 compatibility.
For Python changes, inspect Ruff's diagnostics and formatting suggestions:

```sh
python -m ruff check .
python -m ruff format --check .
```

Ruff configuration and automated quality gates are not set up yet; these commands
use Ruff's defaults and may report existing issues. Distinguish those from your
changes. Avoid reformatting unrelated files or adding broad suppressions just to
make a local check pass. Record any remaining failures in the PR.

## Issues and pull requests

1. Check existing issues and PRs to avoid duplicating work. For a larger feature,
   explain the proposed behavior in an issue before implementing it.
2. Create a branch in your fork, for example `git switch -c fix/retry-behavior`.
3. Make a focused change, add tests where appropriate, and update usage examples
   if behavior changes.
4. Run the tests and checks above. Review `git diff --check` and your diff before
   committing; generated reports and environment files should stay out of the PR.
5. Use a short, descriptive commit message. Existing history uses prefixes such
   as `fix:` and `feat:`; `docs:` and `test:` also describe focused contributions.
6. Open a PR against this repository's default branch. Link the issue, describe
   the before/after behavior, and list the exact checks and Python version used,
   including failures or checks you could not run.

Review may request changes to behavior, tests, documentation, or scope. Keep
follow-up changes in the same PR and explain how you addressed the feedback.
Maintainer availability varies; there is no guaranteed review turnaround.

## Private security reports

Do not publish an exploitable vulnerability, sensitive endpoint, or credentials
in a public issue or PR. Contact the package maintainer privately at
[yunare@gmail.com](mailto:yunare@gmail.com), the author address listed in
`pyproject.toml`, with the subject `a2a-drift security report`.

Include the affected version or commit, expected and actual behavior, potential
impact, and a minimal reproduction using synthetic data and an authorized local
endpoint. Redact secrets. Coordinate a fix and public disclosure with the
maintainer before sharing exploit details.
