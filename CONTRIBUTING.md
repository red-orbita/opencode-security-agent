# Contributing to OpenCode Security Agent

## Getting started

1. Fork and clone the repository
2. Make sure Python 3.8+ is installed
3. Run the test suite: `python3 tests/test_hook.py -v`

## Development workflow

1. Create a feature branch from `main`
2. Make your changes
3. Add or update tests in `tests/test_hook.py`
4. Run the full test suite and ensure all tests pass (55 tests as of v1.3.0)
5. Note: if your changes touch self-protected files (allowlist, IOC database), you must test that the self-protection layer blocks agent writes correctly
6. Submit a pull request

## What to contribute

- **New IOC patterns** -- Add patterns to `references/iocs.json` with tests
- **New threat intelligence sources** -- Add API import scripts to `scripts/`
- **Detection improvements** -- Better regex patterns, fewer false positives
- **Bug fixes** -- Especially bypasses of the detection engine
- **Documentation** -- Improvements to README, threat-sources.md, or SKILL.md

## Code style

- Python: Follow PEP 8. No external dependencies (stdlib only).
- TypeScript: Follow the existing plugin style.
- Shell scripts: Use `set -euo pipefail`. Quote variables.

## Adding IOC patterns

1. Add the pattern to the appropriate section in `references/iocs.json`
2. Add a test case in `tests/test_hook.py` that verifies the pattern is detected
3. If the pattern could cause false positives, add a benign test case too

## Adding API import scripts

1. Create `scripts/import_<provider>.py` based on `scripts/import_template.py`
2. Document the API in `references/threat-sources.md`
3. Add usage examples to the README's "Integrating External IOC APIs" section

## Commit messages

Use conventional commits: `fix:`, `feat:`, `docs:`, `test:`, `chore:`

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0.
