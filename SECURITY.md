# Security

## Threat model

ChangeGuard runs inside a coding agent's session on repositories that may contain untrusted code, file names and git configuration. Its goals:

- `scope` and `check` (pre-approved in `SKILL.md`) never execute repository-controlled commands.
- They never read outside the repository through symlinks, and never write outside their state directory.
- Repository text can't forge ChangeGuard's verdicts.
- `test` executes project code by design, so it is never pre-approved.

## Hardening in place

| Area | Protection |
|---|---|
| Git | Every call disables `core.fsmonitor`, `diff.external`, external diff drivers and textconv (`--no-ext-diff --no-textconv`). Repo `.gitattributes` are ignored via `GIT_ATTR_SOURCE=<empty tree>`, so no filter/diff drivers run. Calls set `GIT_OPTIONAL_LOCKS=0` and `GIT_TERMINAL_PROMPT=0`. |
| File reads | Paths are opened one component at a time with `O_NOFOLLOW` (`openat`-style), so symlinked files and symlinked parent directories are refused without a check-then-use race. Only regular files are read (FIFOs and devices are rejected; `O_NONBLOCK` prevents blocking), and reads are capped (512 KB for source, 4 MB for state). |
| Output | Control and bidi characters in repo-derived text are escaped (`\u000a`). Test output is shown only as `| `-prefixed lines under an "untrusted program output" header. `SKILL.md` tells the agent to treat all of it as data, never as instructions. |
| Test runner | Test paths get a `./` prefix, so file names like `--rootdir=x_test.py` can't become options. Test paths from state files are rejected if they are absolute or contain `..`. Labels are validated. |
| State | State lives in `.git/changeguard/` (or `.changeguard/` outside git). Symlinked or foreign-owned state directories are refused. Writes are atomic (exclusive temp file + `rename` within the opened directory fd). Symlinked state files are never followed or read. The comparison baseline is loaded before any test code runs. |

## Residual risks

- **`test` runs untrusted code.** Test suites, `conftest.py`, `package.json` scripts and `--cmd` can do anything the user can do. Only run `test` in repositories you trust, or in a sandbox or container.
- **Same-user state tampering.** Code run by `test`, or any process running as you, can edit `.git/changeguard/*.json` or the working tree between commands (for example changing `allowed` or the pre-edit snapshot before `check`). ChangeGuard reduces this window; it can't prevent it. Verdicts are evidence, not a security boundary.
- **Git older than 2.40** ignores `GIT_ATTR_SOURCE`. There, a repository that ships both a `.gitattributes` `filter=` entry and a matching `filter.<name>.clean` in its own `.git/config` can still run a clean filter during `check`. Use git 2.40 or later with untrusted repositories.
- **Ignoring attributes changes diffs.** Git LFS and other filtered files may show as modified (raw content vs. index). Repo-defined diff drivers aren't used.
- **Prompt injection** is mitigated by escaping and instructions, not eliminated. An agent can still be persuaded by plausible-looking text in code or test output, so review HIGH-impact actions.
- **Windows** has no `dir_fd`/`O_NOFOLLOW`, so ChangeGuard uses a fallback:
  - A case-insensitive realpath containment check catches symlinked or junctioned parent folders. `islink` catches symlinked files.
  - Junction state folders are refused (Python 3.12 or later).
  - Paths containing `\` or `:` (drives, alternate data streams) are rejected.
  - Files are opened in binary mode, so Ctrl-Z can't truncate a scan.
  - Output is written with `backslashreplace`, so legacy console encodings can't crash it.
  - Remaining gaps: a small time-of-check/time-of-use window between the containment check and the open, because a component can be swapped in between. There is no owner check on the state folder (no POSIX uid). Hard links aren't detected; this applies on every OS, though Linux usually restricts cross-user hard links. The junction and Ctrl-Z tests have only been run on Windows by users, not in CI here.
- **`--cmd` uses the platform shell:** `sh` on POSIX, `cmd.exe` on Windows. Write commands for the platform you're on, or use a portable `python -c ...` form.
- **Detection is heuristic.** Missing findings don't prove a change is safe.

## Reporting a vulnerability

Please report privately through the repository's GitHub security advisory ("Report a vulnerability"), not in a public issue.
