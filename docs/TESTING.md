# Testing Strategy

This project is split into three CLI entry points (`audit`, `fetch`, `scan`). The
suite mirrors that structure so tests stay close to the behaviours they protect.

```
tests/
  audit/
    test_audit_cli.py        # smoke/integration checks for scripts.audit
  fetch/
    test_fetch_cli.py        # fetch_sources and CLI flag behaviour
  scan/
    test_scan_cli.py         # end-to-end scanner run over a synthetic workspace
    test_scan_components.py  # focused parser/traversal helpers powering the CLI
```

## Audit CLI (`scripts.audit`)

- Verifies flag interactions (`--skip-*` combinations) and wiring between
  fetch/scan phases.
- Uses monkeypatched helpers so tests stay fast and deterministic.

## Fetch CLI (`scripts.fetch`)

- Fakes HTTP responses to validate consolidation logic, parser hints, and
  `fetch_sources` output structure.
- Covers `--show-parsers` and configuration validation errors so misconfigurations
  are surfaced early.

## Scan CLI (`scripts.scan`)

- `test_scan_cli.py` drives the full CLI with an advisory + manifest/lockfile tree,
  asserting both JSON and text outputs include all expected findings and summaries.
- `test_scan_components.py` locks down the bespoke parsers (`yarn.lock`,
  `pnpm-lock.yaml`), advisory ingestion, and traversal statistics used by the CLI.

## Adding New Tests

1. Decide which CLI or helper the behaviour belongs to and place the test under
   the matching folder.
2. Prefer table-driven helpers and temporary directories (`tmp_path`) to keep
   fixtures minimal and isolated.
3. If new data formats are introduced, extend `test_scan_components.py` or create
   a sibling module with clear naming (`test_scan_<area>.py`).
4. Run `pytest` and include evidence in PRs (`## Testing` section).

## Running the Suite

```
pytest            # run everything
pytest tests/scan # focus on scanner tests
pytest --cov --cov-report=term-missing  # include line coverage summary
```

Tests rely solely on stdlib and pytest; no network calls are made thanks to monkeypatching.
