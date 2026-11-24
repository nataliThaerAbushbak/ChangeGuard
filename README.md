# ChangeGuard

A Claude Code skill that guards against unintended code changes and regressions. Before an edit, it maps what depends on the code. After the edit, it checks what actually changed and whether any tests broke.

The analysis is done by one stdlib-only Python script, so the results are deterministic and the agent doesn't have to rely on guesswork. Output is compact, and the script only scans the files that matter.

## Install

```bash
# personal (all projects)
mkdir -p ~/.claude/skills && cp -r skills/changeguard ~/.claude/skills/
# or per project (commit it to share with your team)
mkdir -p .claude/skills && cp -r skills/changeguard .claude/skills/
```

Requires Python 3.8+ and git. There are no other dependencies.

## Use

In Claude Code:

```
/changeguard fix the rounding bug in src/billing/invoice.py
```

Claude may also load the skill on its own for risky edits. The workflow is scope → baseline tests → minimal edit → diff check → test compare → short report.

The script also works directly, for example in CI:

```bash
CG=skills/changeguard/scripts/changeguard.py
python3 $CG scope src/utils.py --symbol add      # risk, dependents, tests, public API
python3 $CG test --label before                  # baseline of related tests
# ... edit ...
python3 $CG check                                # diff findings; exit 1 on HIGH
python3 $CG test --label after --compare before  # per-test regressions
```

Example output:

```
[MEDIUM] src/utils.py  deps=1 tests=1 public=3
  why: imported by 2 files (1 test); public API used elsewhere
...
HIGH src/utils.py: removed public `add` still referenced in: src/app.py
...
Tests [after]: FAILED (exit 1) 1 passed, 1 failed, 0 error, 0 skipped in 0.31s
vs [before]: regressions 1, new failures 0, fixed 0, not re-run 0
  REGRESSED: tests/test_utils.py::T::test_add
```

See [`skills/changeguard/reference.md`](skills/changeguard/reference.md) for flags, risk scoring and findings.

## Limits

The analysis is heuristic and works on text and imports, not on a full type or call graph. Python, JS/TS and Go get the deepest checks. For other languages it does dependent search and diff checks only. When a test run doesn't happen, the result says `NOT RUN` and is never reported as passed.

## Security

Only `scope` and `check` are pre-approved. Neither executes repository-configured git commands, and neither reads through symlinks. `test` runs project code and always asks first. Script output that quotes repository content is marked as untrusted. See [SECURITY.md](SECURITY.md) for the threat model and residual risks; in short, run `test` only in repositories you trust, and use git 2.40 or later.

## Development

```bash
python3 -m unittest discover -s tests   # or: pytest tests
```

## License

MIT
