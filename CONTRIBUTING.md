# Contributing to Shai-Hulud Audit Toolkit

Thank you for your interest in contributing to the Shai-Hulud Audit Toolkit!

## Getting Started

Please read our [Agent Primer (AGENTS.md)](AGENTS.md) for comprehensive development guidelines, project architecture, and detailed workflow instructions.

## Quick Contribution Guide

1. **Fork the repository** and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Set up your development environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements-dev.txt
   pip install -e .
   ```

3. **Make your changes** following our code standards (see below)

4. **Run tests** to ensure everything works:
   ```bash
   pytest --cov --cov-report=term-missing --cov-fail-under=80
   ```

5. **Lint your code**:
   ```bash
   ruff check .
   ```

6. **Commit your changes** with a descriptive message:
   ```bash
   git commit -m "feat: add support for new advisory source"
   ```

7. **Submit a pull request** to the appropriate branch (see [Branching Strategy](#branching-strategy))

## Code Standards

- **Python 3.10+** required
- **Type annotations** for all public functions
- **80% test coverage minimum** (enforced by CI)
- **Ruff** for linting and formatting
- **Line length**: 140 characters
- **Quotes**: Double quotes
- **Indentation**: Spaces (not tabs)
- **Stdlib-only dependencies** (avoid external packages unless compelling reason)

### Code Quality Principles

- **KISS**: Keep it simple, stupid
- **YAGNI**: You aren't gonna need it
- **Clarity > Cleverness**: Code should be obvious
- **Module size**: ≤ 500 lines (hard limit)
- **Function size**: ≤ 50 lines (guideline)
- **Nesting depth**: ≤ 2 levels for business logic

See [CLAUDE.md](CLAUDE.md) for detailed quality guidelines.

## Branching Strategy

Based on our workflow documented in [AGENTS.md](AGENTS.md):

### Branch Types
- `feat/<topic>` - New features
- `fix/<topic>` - Bug fixes
- `docs/<topic>` - Documentation only
- `chore/<topic>` - Maintenance tasks

### Active Development
- Check if there's an active `release/x.y.z` branch
- If yes, merge your feature branch into the release branch
- If no, create a PR to `main`

## What to Contribute

We welcome contributions in these areas:

### High Priority
- New advisory source parsers
- Pattern detection improvements
- Performance optimizations
- Documentation enhancements
- Test coverage improvements

### Ideas
- Additional output formats
- Integration with other security tools
- Improved error messages
- CI/CD examples for other platforms

## Testing

- Add unit tests for new functions
- Add integration tests for new workflows
- Maintain 80%+ coverage (CI enforces this)
- Test both positive and negative cases
- Place test fixtures under `tests/` directory

Run tests:
```bash
# All tests
pytest

# With coverage report
pytest --cov --cov-report=term-missing

# Specific test file
pytest tests/test_scan.py

# Verbose output
pytest -v
```

## Documentation

When adding features:
- Update [README.md](README.md) if user-facing
- Update [docs/USAGE.md](docs/USAGE.md) with examples
- Add entry to [CHANGELOG.md](CHANGELOG.md) under "Unreleased"
- Update code docstrings
- Include log snippets in issue reports

## Issue Reporting

When filing issues, please include:
- Python version
- Operating system
- Relevant log excerpts from `logs/`
- Steps to reproduce
- Expected vs actual behavior

## Code Review Process

1. PR must pass CI checks (tests + linting)
2. Maintain or improve test coverage
3. Update documentation as needed
4. Address review feedback
5. Squash commits if requested

## Release Process

(For maintainers)

1. Create `release/x.y.z` branch from `main`
2. Merge feature branches into release branch
3. Update `pyproject.toml` version
4. Update `CHANGELOG.md` (move Unreleased → vX.Y.Z with date)
5. Create PR from `release/x.y.z` → `main`
6. Tag after merge: `git tag vX.Y.Z`

## Questions?

- Check [AGENTS.md](AGENTS.md) for detailed guidance
- Check [docs/USAGE.md](docs/USAGE.md) for usage examples
- Open an issue for discussion
- Review existing issues and PRs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for helping make Shai-Hulud Audit Toolkit better!**
