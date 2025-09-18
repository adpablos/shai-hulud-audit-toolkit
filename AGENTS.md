# Shai-Hulud Audit Toolkit – Agent Primer

This document gathers the key facts about the repository so every agent shares a
common mental model of the project.

## Mission

Provide a small toolkit that fetches the latest Shai-Hulud npm compromise
advisories and audits local directories (or entire machines) for matching
`package@version` combinations.

## Principles

- Favour simple flows and small helpers over sprawling scripts.
- Optimise for clarity: explicit paths, explicit logs, no hidden work.
- Prefer changes that are easy to delete or extend; avoid bespoke abstractions
  unless they remove real duplication.

## Codebase Layout

```
config/
  shai_hulud_sources.json    # Advisory URLs + parser hints

scripts/
  __init__.py                # Makes the package importable
  audit.py                   # Orchestrates fetch + scan (run(argv))
  fetch.py                   # Advisory fetch CLI (run(argv))
  scan.py                    # Scanner CLI (run(argv))

data/.gitkeep                # Placeholder; generated advisory JSON ignored
logs/.gitkeep                # Placeholder; generated logs ignored

docs/USAGE.md               # Extended workflows & troubleshooting
CHANGELOG.md                 # Release notes (semantic versioning)
README.md                    # Overview + quick start + installation
pyproject.toml               # Packaging metadata, console scripts, Ruff config
requirements*.txt            # Runtime & dev dependencies
.github/workflows/ci.yml     # GitHub Actions (ruff + pytest)
```

## CLI Entrypoints

`pyproject.toml` exposes:
- `shai-hulud-audit` → `scripts.audit:run`
- `shai-hulud-fetch` → `scripts.fetch:run`
- `shai-hulud-scan`  → `scripts.scan:run`

The default audit (`scripts/audit.py`) fetches advisories into
`data/compromised_shaihulud.json`, then scans the user’s `$HOME`, including
`node_modules` and global npm packages. Flags:
- `--skip-fetch` / `--skip-scan`
- `--skip-node-modules` / `--skip-global`
- `--json`
- positional paths to override the default `$HOME`

## Fetching

- Sources configured in `config/shai_hulud_sources.json`
- Parser hints validated against `stepsecurity_table`, `ox_table`, `wiz_list`
  (list via `python3 scripts/fetch.py --show-parsers`)
- Fetch logs include per-source package counts and a success/failure summary

## Scanning

- Inspects manifests (`package.json`) and lockfiles for exact version matches
- Optional traversal of installed modules (`node_modules`)
- Optional global npm inspection using `npm ls -g --json`
- Known malformed fixtures (e.g., `resolve` tests) are muted after the first
  occurrence

## Tooling & Quality

- Lint: `ruff check .` (configured for line length 140, ignores E203/E402)
- Tests: `pytest`
- CI: `.github/workflows/ci.yml` runs both lint + tests on push/PR
- Packaging: `pyproject.toml` with `project.version = "0.1.0"`
- Project licensed under MIT

## Coding Standards & Tooling

- Python 3.10+, type-annotated functions, `pathlib.Path` first; reuse helpers
  like `DEFAULT_PATHS` rather than re-rolling logic.
- Ruff defines style (140 cols, double quotes, spaces). Run `ruff check .` and
  fix the drift.
- Keep modules import-safe by funnelling work through `run(argv)` or pure
  helpers; avoid import-time side effects.
- Stick with the existing CLI tone: `logging.getLogger` plus short `[phase]`
  status lines that mention the relevant path or action.
- Stay stdlib-only unless there is a compelling reason; if one arises, update
  both requirements files and explain why.

## Development Workflow

- `python -m venv .venv`
- `pip install -r requirements-dev.txt && pip install -e .`
- `ruff check .`
- `pytest`
- `pytest --cov --cov-report=term-missing --cov-fail-under=80` mirrors CI's coverage gate
- Optional: quick audit run with `--skip-fetch` when touching scan logic.

## Logging & Error Handling

- Preserve `[fetch]` / `[scan]` prefixes so logs stay grep-friendly.
- Propagate non-zero exits for findings or misconfig (`scripts/audit.py` uses
  `2`); cover new branches with tests.
- HTTP failures should log the URL and parser—enough to reproduce, nothing
  noisy.

## Releases & Changelog

- `CHANGELOG.md` records every release; current entry `v0.1.0` covers the
  initial public drop (script renames, parser validation, skip flags, lint/tests)
- Keep a short "Unreleased" section at the top of `CHANGELOG.md` and drop one
  bullet there per merged PR; promote it to a dated version entry when cutting a
  release.
- Cut releases from a short-lived `release/x.y.z` branch: bump
  `project.version` in `pyproject.toml`, polish the changelog, then merge via PR
  and tag.
- For urgent behavioural fixes that need shipping immediately, it's acceptable
  to bump the version and changelog in the feature branch itself, but prefer
  batching on the release branch.

## Git Workflow

- Branch names follow `<type>/<topic>`: use `fix/` for bug fixes, `feat/` for new
  functionality, `docs/` for documentation-only updates, and `chore/` for
  maintenance. Keep the topic kebab-cased (e.g., `fix/package-discovery`).
- Commits use the pattern `<type>: <imperative summary>` with the same `type`
  values as branches (for example, `fix: handle package discovery explicitly`).
- Pull request titles mirror the main commit summary and enumerate key changes
  plus test evidence in the body (`## Summary` / `## Testing`).
- Always work on a feature branch, push it to origin, and open a PR; merge via
  the PR after reviews/tests instead of using local fast-forwards.

## Housekeeping

- `.gitignore` excludes generated artifacts (`logs/`, `data/`, `__pycache__/`,
  `.ruff_cache/`, `.pytest_cache/`, virtualenvs, IDE folders)
- `.gitkeep` files keep the placeholder directories in Git
- No commits of generated advisory/log files; they are runtime artefacts only

## Contributing Notes

- Keep README and `docs/USAGE.md` examples in sync with reality.
- Behaviour changes: update `CHANGELOG.md`, bump the version, adjust fixtures.
- Bug reports/PRs include the relevant fetch/scan log snippet.
- Never commit runtime artefacts; add fixtures under `tests/` when needed.
