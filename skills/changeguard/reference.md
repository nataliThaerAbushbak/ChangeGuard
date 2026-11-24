# ChangeGuard reference

## Commands

| Command | Purpose | Key flags |
|---|---|---|
| `scope PATH...` | Dependents, related tests, public symbols and risk for each target. Records the baseline commit, the allowed files and a snapshot of already-dirty files. | `--symbol NAME`, `--append`, `--json`, `--limit N` |
| `check` | Compares the diff against the baseline commit, including staged, unstaged and untracked files. Ignores files that were dirty before `scope` and are unchanged since. | `--base REF`, `--max-lines N`, `--json` |
| `test [FILES]` | Runs tests (defaults to the scope's related tests), saves per-test results under a label, and compares against an earlier label. | `--label`, `--compare`, `--all`, `--cmd`, `--runner`, `--timeout`, `--tail` |

State is stored in `.git/changeguard/`, or in `.changeguard/` outside git, so it never appears in the diff.

## Exit codes

`0` ok · `1` HIGH finding, failing tests or regression · `2` usage error (e.g. invalid label) · `3` verification not run or incomplete (no prior run to compare, tests from the earlier run missing now, or previously passing tests now skipped).

Labels may contain only letters, digits, `_`, `-` and `.`, up to 64 characters, and `--compare` must differ from `--label`.

## Risk scoring (scope)

Points are summed per file. 0–1 is LOW, 2–3 MEDIUM, 4 or more HIGH.

- Imported by other files: 1–3 files = 1 point, 4–10 = 2, more than 10 = 3.
- Exports public symbols that other files use: +1.
- Sensitive path (migration, manifest, lockfile, CI, auth/security/payment, package entry point, config, schema): +2.
- No related tests: +1.
- New files are always LOW.

Dependents are found by running `git grep -w <module stem>` over source files, then keeping only lines that look like import, require, include or use statements, or quoted paths ending in `/<stem>`. This is a heuristic: dynamic imports and re-exports can be missed.

## Findings (check)

| Severity | Finding |
|---|---|
| HIGH | A public symbol was removed but is still referenced elsewhere; a signature changed in an incompatible way while referencing files were left unmodified; a test file was deleted; a test lost assertions or gained a skip/only marker; a merge-conflict marker; a possible hard-coded secret. |
| MED | A file outside the planned scope changed (marked "may contain user work, do not revert" if it already had uncommitted edits before `scope`); a dependency manifest, lockfile, migration or CI file changed; a file was deleted; a public symbol was removed with no in-repo references; a symbol moved to another file. |
| LOW | Optional parameters were added (looks compatible); a debug leftover (`breakpoint()`, `pdb`, `console.log`, `debugger`); a large diff; no scope was recorded. |

Public symbols are detected in Python (`def`, `class`; names starting with `_` are skipped), JS/TS (`export ...`) and Go (capitalised `func`/`type`).

## Test runners

Auto-detection picks pytest (if it is installed) or unittest for `.py` files, `go test -v` for Go, and `npm test` when a `package.json` exists. Per-test regression diffs work for pytest, unittest and Go. With `--cmd` or npm, only the exit code is compared ("SUITE REGRESSED").
