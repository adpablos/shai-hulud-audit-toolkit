# Claude Code Guidance for Shai-Hulud Audit Toolkit

This document provides Claude-specific guidance for working on this project. For general project information, **always refer to [`AGENTS.md`](AGENTS.md)** first.

## Quick Reference

**Primary Documentation**: [`AGENTS.md`](AGENTS.md) contains the authoritative project guide.

**Current Version**: 0.2.0
**Active Branch**: `release/0.2.0`
**Next Steps**: Implement UX and documentation improvements (issues #10-#16)

## Branching Strategy Summary

Based on AGENTS.md workflow:

### Branch Types
- `feat/<topic>` - New features
- `fix/<topic>` - Bug fixes
- `docs/<topic>` - Documentation only
- `chore/<topic>` - Maintenance tasks
- `release/x.y.z` - Release preparation

### Release Process
1. Create `release/x.y.z` branch from `main`
2. Merge completed feature branches into release branch
3. Update `pyproject.toml` version
4. Update `CHANGELOG.md` (move Unreleased → vX.Y.Z with date)
5. PR from `release/x.y.z` → `main`
6. Tag after merge

### Commit Message Format
```
<type>: <imperative summary>

Optional body with details.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

**User Preference**: Balanced verbosity - descriptive but concise. Not too verbose, not too terse.

## Project Priorities

### Phase 1: Quick Wins (Current)
From `release/0.2.0`:
- ~~Issue #16: Repository metadata updates~~ ✅ Completed
- ~~Issue #10: Color-coded terminal output~~ ✅ Completed
- Issue #11: Emoji-based risk indicators (1 day) ← **NEXT**
- Issue #12: Structured summary report (2-3 days)
- Issue #15: Documentation enhancements (ongoing)

### Phase 2: Feature Enhancements
- Issue #13: Extended suspicious code pattern detection
- Issue #14: Data exfiltration pattern detection
- Issue #6: Script & workflow IOCs (existing)
- Issue #7: Namespace warnings (existing)

## Development Commands

```bash
# Setup
python -m venv .venv
pip install -r requirements-dev.txt && pip install -e .

# Quality checks
ruff check .
pytest
pytest --cov --cov-report=term-missing --cov-fail-under=80

# Testing scan logic without fetch
shai-hulud-audit --skip-fetch --advisory data/compromised_shaihulud.json
```

## Code Style Notes

### From AGENTS.md
- Python 3.10+, type-annotated functions
- Use `pathlib.Path` over string paths
- Line length: 140 characters
- Double quotes, spaces (not tabs)
- Keep `[fetch]` / `[scan]` prefixes in logs
- Stdlib-only dependencies (no external packages unless compelling reason)

### Code Quality & Size Limits

**Core Principles** (always apply):
- **KISS (Keep It Simple, Stupid)**: Simple solutions over complex ones
- **YAGNI (You Aren't Gonna Need It)**: Don't add code "just in case"
- **Clarity > Cleverness**: Code should be obvious, not clever
- **Simple > Complex**: Prefer straightforward approaches
- **Reuse > Reinvent**: Use existing patterns and helpers
- **No legacy code**: All code is first-class; no "deprecated-but-kept" patterns

**Style & Standards**:
- PEP 8 compliance
- **Type hints** on all public functions and data structures
- Line length: 140 characters
- Double quotes, spaces (not tabs)
- Lint: `ruff check .` must pass with zero errors

**Size & Complexity Targets**:
- **Module size**: ≤ 500 lines (hard limit)
- **Function size**: ≤ 50 lines (guideline, not dogma)
  - CLI parsers and data structures may reasonably exceed this
  - Business logic should stay well under 50 lines
  - If a function is >70 lines, strongly consider refactoring
- **Nesting depth**: ≤ 2 levels for business logic
  - Data structures (dicts, lists) don't count toward nesting
  - Early returns/continues are encouraged to reduce depth
  - Deep nesting usually signals need for helper functions

**What to Remove**:
- Dead code (unused functions, commented code)
- Magic numbers (use named constants)
- Duplication (extract to helpers after 2nd occurrence)
- "Legacy" terminology (implies technical debt we don't want)

**Pragmatic Application**:
- **New code (0.2.0+)**: Follow these standards
- **Existing code**: Refactor when touched; no need for mass rewrites
- **Be pragmatic**: A 55-line function that's crystal clear > two 30-line functions that obscure logic
- **Focus on real complexity**: Deep nesting in business logic is bad; data structure nesting is fine
- **Maintainability first**: If splitting makes code harder to understand, don't split

### Claude-Specific Reminders
- Always read files before editing them
- Use `Edit` tool for modifications, not `Write`
- Preserve exact indentation from Read tool (ignore line number prefix)
- Check git status before creating commits
- **ALWAYS run quality checks before committing** (see checklist below)
- Update CHANGELOG.md "Unreleased" section for new features

### Pre-Commit Quality Checklist (MANDATORY)

**Run these commands before EVERY commit:**

```bash
# 1. Linting (must pass with zero errors)
ruff check .

# 2. Tests (must pass with 80%+ coverage)
pytest --cov --cov-report=term-missing --cov-fail-under=80

# 3. Only commit if BOTH pass
git add <files>
git commit -m "..."
```

**Never skip these checks.** If you push code that fails linting or tests, the CI will fail and block the release. Always verify locally first.

**When to run:**
- ✅ After adding/modifying any code
- ✅ After changing imports or function signatures
- ✅ After refactoring
- ✅ Before every `git commit`
- ✅ Before every `git push`

**Red flags that mean you MUST run checks:**
- 🚨 Modified any `.py` file
- 🚨 Added/removed imports
- 🚨 Changed function signatures
- 🚨 Modified tests
- 🚨 About to commit or push

## File Locations

```
config/shai_hulud_sources.json    # Advisory source URLs
scripts/
  audit.py                        # Main orchestrator
  fetch.py                        # Advisory fetcher
  scan.py                         # Scanner implementation
data/                             # Generated advisories (gitignored)
logs/                             # Generated logs (gitignored)
tests/                            # Pytest test suite
docs/
  USAGE.md                        # User-facing documentation
  TESTING.md                      # Test suite documentation
```

## Common Tasks

### Adding a New CLI Flag
1. Add argparse argument in `parse_args()`
2. Thread through to relevant functions
3. Update README.md and docs/USAGE.md
4. Add CHANGELOG.md entry under "Unreleased"
5. Add test coverage
6. Run `ruff check .` and `pytest`

### Adding a New Feature
1. Create feature branch: `git checkout -b feat/feature-name`
2. Implement with tests (maintain 80%+ coverage)
3. Update CHANGELOG.md "Unreleased" section
4. Update documentation (README, USAGE)
5. Push and create PR (or merge to release branch if active)
6. Ensure CI passes

### Creating a Release
1. Create `release/x.y.z` from main
2. Merge all feature branches to release branch
3. Update `pyproject.toml` version
4. Update `CHANGELOG.md` (Unreleased → vX.Y.Z + date)
5. Commit: "chore: prepare release vX.Y.Z"
6. Create PR to main
7. Tag after merge

## Testing Philosophy

- Unit tests for parsers and helpers
- Integration tests for CLI workflows
- Fixtures under `tests/` (never commit runtime artifacts)
- Aim for 80%+ coverage (CI enforces this)
- Test both positive and negative cases
- Known malformed fixtures (like `resolve` tests) should be suppressed

## Documentation Standards

- Keep README.md examples in sync with reality
- Update docs/USAGE.md for new flags and workflows
- Include log snippets in issue reports
- Examples should use real commands that actually work
- No emoji in code/docs unless explicitly requested by user

## Security Considerations

**This is a defensive security tool.**

- All detection features are for defense only
- Never assist with creating malicious code
- Pattern detection may have false positives - document this
- Provide clear remediation guidance with findings
- Encourage manual review of flagged issues

## Working with Issues

### Issue Labels from GitHub
- **Priority 1** (Quick Wins): #10, #11, #12, #15
- **Priority 2** (Features): #6, #7, #8, #13, #14
- **Completed**: #9 (npm cache), #16 (repository metadata)

### Issue Implementation Checklist
- [ ] Create feature branch
- [ ] Implement functionality with tests
- [ ] Update CHANGELOG.md "Unreleased"
- [ ] Update README.md if user-facing
- [ ] Update docs/USAGE.md with examples
- [ ] Run `ruff check .` and `pytest --cov`
- [ ] Merge to release branch (if active) or create PR to main
- [ ] Close GitHub issue with `gh issue close <number> --comment "<summary>"`

## References

- **Primary Guide**: [AGENTS.md](AGENTS.md)
- **Usage Guide**: [docs/USAGE.md](docs/USAGE.md)
- **Testing Guide**: [docs/TESTING.md](docs/TESTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

**Note**: This document is supplementary. When in doubt, refer to [AGENTS.md](AGENTS.md).
