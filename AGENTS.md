# AGENTS.md

## Tests

The comprehensive test suites for this repository live in
[github.com/org-ai-assisted/dist-ai](https://github.com/org-ai-assisted/dist-ai),
not in-tree, and run on each pull request and push via
`.github/workflows/consumer-dist-ai-tests.yml`. They are too high-volume for
routine human review.

### Coverage gate

The 100% gate (`dist-ai usr/bin/secure-terminal-tests-coverage`) measures
STATEMENT coverage only: `coverage run --parallel-mode --source=<pkg>` with NO
`--branch`, then `coverage report --fail-under=100`. A local `coverage run
--branch` spot-check reports branch PARTIALS the gate never counts (e.g. a
genexpr `N->N-1 / N->exit`), sending you hunting a nonexistent gap. Match the
gate: drop `--branch`.
