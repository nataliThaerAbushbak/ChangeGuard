#!/usr/bin/env python3
"""ChangeGuard: deterministic pre/post-change analysis for coding agents.

Subcommands:
  scope PATH...   analyze targets: dependents, related tests, public API, risk
  check           inspect the git diff against the scope baseline
  test            run relevant tests, save results, compare with a prior run

Stdlib only. Output is compact text by default; pass --json for full data.
Exit codes: 0 ok, 1 HIGH findings / test failures or regressions, 2 usage error,
3 verification not run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
SRC_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".java",
           ".kt", ".rs", ".php", ".cs", ".swift", ".c", ".h", ".cc", ".cpp", ".hpp",
           ".vue", ".svelte", ".scala", ".dart"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".changeguard", ".tox", ".mypy_cache", ".pytest_cache", "target", "vendor", ".next"}
MAX_WALK_FILES = 20000
MAX_READ_BYTES = 512 * 1024
MAX_CANDIDATES = 300
SEV_ORDER = {"HIGH": 0, "MED": 1, "LOW": 2}
GENERATED_EXT = {".pyc", ".pyo", ".class", ".o", ".obj", ".so", ".dll", ".exe", ".log"}

LANG = {".py": "py", ".go": "go"}
LANG.update({e: "js" for e in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")})
SYM_PATTERNS = {
    "py": [re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z]\w*)\s*\("),
           re.compile(r"^\s*class\s+([A-Za-z]\w*)")],
    "js": [re.compile(r"^\s*export\s+(?:default\s+)?(?:declare\s+)?(?:async\s+)?(?:abstract\s+)?"
                      r"(?:function\*?|class|const|let|var|interface|type|enum)\s+([A-Za-z_$][\w$]*)")],
    "go": [re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Z]\w*)"), re.compile(r"^type\s+([A-Z]\w*)")],
}
TEST_RE = re.compile(r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]+\.py$|_test\.(py|go)$|"
                     r"\.(test|spec)\.[cm]?[jt]sx?$|Tests?\.(java|kt|cs)$", re.I)
SENSITIVE = [
    (r"(^|/)(migrations?|alembic)/", "database migration"),
    (r"(^|/)(package\.json|pyproject\.toml|setup\.py|setup\.cfg|requirements[^/]*\.txt|go\.mod|"
     r"Cargo\.toml|Gemfile|pom\.xml|build\.gradle(\.kts)?)$", "dependency manifest"),
    (r"(^|/)([^/]*\.lock|package-lock\.json|go\.sum)$", "lockfile"),
    (r"(^|/)\.github/workflows/|\.gitlab-ci\.yml$|(^|/)Dockerfile|docker-compose", "CI/deploy config"),
    (r"auth|security|crypto|payment|billing|permission|secret", "security-sensitive area"),
    (r"(^|/)(__init__\.py|index\.[cm]?[jt]sx?|mod\.rs|lib\.rs)$", "package entry point"),
    (r"(^|/)(settings|config)[^/]*\.(py|json|ya?ml|toml|ini)$|(^|/)\.env", "configuration"),
    (r"\.(sql|proto|graphql)$|openapi|(^|/)schema", "schema/contract"),
]
IMPORT_KW = re.compile(r"\b(import|from|require|include|use|using)\b")
SKIP_MARK = re.compile(r"@pytest\.mark\.skip|@unittest\.skip|\.skip\(|\bxit\(|\bxdescribe\(|"
                       r"\bt\.Skip\(|\.only\(|@Disabled|@Ignore")
ASSERT_RE = re.compile(r"\bassert|\bexpect\(|\.should\b|\bt\.(Error|Fatal)")
SECRET_RE = re.compile(r"(?i)(api[_-]?key|secret|passw(or)?d|token|private[_-]?key)\s*[:=]\s*"
                       r"['\"][^'\"\s]{8,}['\"]|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}")
CONFLICT_RE = re.compile(r"^(<{7}|>{7})( |$)|^={7}$")
DEBUG_RE = re.compile(r"^\s*breakpoint\(\)|\bpdb\.set_trace\(|^\s*import i?pdb\b|"
                      r"\bconsole\.log\(|^\s*debugger;?\s*$")


# ---------------------------------------------------------------- helpers
def run(cmd, cwd, timeout=None, shell=False, extra_env=None):
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(extra_env or {})}
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                          shell=shell, errors="replace", env=env)


GIT_SAFE = ["-c", "core.quotepath=false", "-c", "core.fsmonitor=false", "-c", "diff.external=",
            "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false", "-c", "color.ui=false"]
# Attributes from the empty tree: repo .gitattributes can't select filter/textconv/diff drivers
# (git >= 2.40; older git ignores the variable). No optional index writes during reads.
GIT_ENV = {"GIT_ATTR_SOURCE": EMPTY_TREE, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
           "GIT_EXTERNAL_DIFF": ""}


def git(args, root):
    if args and args[0] == "diff":
        args = ["diff", "--no-ext-diff", "--no-textconv", *args[1:]]
    return run(["git", *GIT_SAFE, *args], root, extra_env=GIT_ENV)


def is_git(root: Path) -> bool:
    return git(["rev-parse", "--is-inside-work-tree"], root).stdout.strip() == "true"


def find_root(arg):
    start = Path(arg or os.getcwd()).resolve()
    r = git(["rev-parse", "--show-toplevel"], start)
    return Path(r.stdout.strip()).resolve() if r.returncode == 0 and r.stdout.strip() else start


def state_dir(root: Path) -> Path:
    r = git(["rev-parse", "--git-dir"], root)
    if r.returncode == 0 and r.stdout.strip():
        d = Path(r.stdout.strip())
        return (d if d.is_absolute() else root / d) / "changeguard"
    return root / ".changeguard"


NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRFLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
DIR_FD_OK = os.open in os.supports_dir_fd and NOFOLLOW != 0
MAX_STATE_BYTES = 4 * 1024 * 1024


def _parent_fd(base: Path, relpath: str):
    """Open the parent dir of base/relpath one component at a time, never following
    symlinks (race-free against swapped components). Returns (dir_fd, last_name)."""
    parts = relpath.split("/")
    if not relpath or relpath.startswith("/") or any(x in ("", ".", "..") for x in parts):
        raise OSError("unsafe relative path")
    if not DIR_FD_OK:  # fallback (e.g. Windows): containment check, small TOCTOU window
        parent = (base / relpath).parent
        if os.path.realpath(parent) != os.path.join(os.path.realpath(base), *parts[:-1]):
            raise OSError("symlinked parent")
        return None, str(base / relpath)
    fd = os.open(base, DIRFLAGS)
    try:
        for comp in parts[:-1]:
            nfd = os.open(comp, DIRFLAGS | NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
    except OSError:
        os.close(fd)
        raise
    return fd, parts[-1]


def _open_rel(base: Path, relpath: str):
    """Open a regular file under base for reading: no symlinks, devices or FIFOs."""
    dfd, name = _parent_fd(base, relpath)
    try:
        if dfd is None and os.path.islink(name):
            raise OSError("symlink")
        fd = os.open(name, os.O_RDONLY | NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                     **({"dir_fd": dfd} if dfd is not None else {}))
    finally:
        if dfd is not None:
            os.close(dfd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError("not a regular file")
    return os.fdopen(fd, "rb")


def read_bytes(base: Path, relpath: str, limit=MAX_READ_BYTES):
    try:
        with _open_rel(base, relpath) as f:
            data = f.read(limit + 1)
    except OSError:
        return None
    return None if len(data) > limit else data


def load_json(path: Path):
    data = read_bytes(path.parent.parent, f"{path.parent.name}/{path.name}", MAX_STATE_BYTES)
    try:
        val = json.loads(data) if data is not None else None
    except ValueError:
        return None
    return val if isinstance(val, dict) else None


def save_json(path: Path, data):
    """Atomic write; refuses a symlinked or foreign-owned state directory."""
    d = path.parent
    try:
        d.mkdir(mode=0o700)
    except FileExistsError:
        pass
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or (hasattr(os, "getuid") and st.st_uid != os.getuid()):
        sys.exit(f"changeguard: refusing unsafe state directory {d} (symlink or not owned by you)")
    body = json.dumps(data, indent=1).encode()
    tmp = f".tmp-{os.getpid()}-{time.time_ns()}-{path.name}"
    if not DIR_FD_OK:
        (d / tmp).write_bytes(body)
        os.replace(d / tmp, path)
        return
    dfd = os.open(d, DIRFLAGS | NOFOLLOW)  # fails if d was swapped for a symlink
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=dfd)
        with os.fdopen(fd, "wb") as f:
            f.write(body)
        os.replace(tmp, path.name, src_dir_fd=dfd, dst_dir_fd=dfd)  # replaces links, never follows
    except OSError as e:
        sys.exit(f"changeguard: could not write state file {path}: {e}")
    finally:
        os.close(dfd)


def rel(root: Path, p: str) -> str:
    ap = Path(p)
    ap = (ap if ap.is_absolute() else Path.cwd() / ap).resolve()
    try:
        return ap.relative_to(root).as_posix()
    except ValueError:
        sys.exit(f"changeguard: {p} is outside repository root {root}")


def read_text(root: Path, relpath: str) -> str:
    data = read_bytes(root, relpath)
    return "" if data is None else data.decode("utf-8", "replace")


def sha1(root: Path, relpath: str):
    h = hashlib.sha1()
    try:
        with _open_rel(root, relpath) as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        try:  # symlink: hash its target text, as git does
            return "link:" + os.readlink(root / relpath)
        except OSError:
            return "missing"


CTRL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\n]")


def safe(text) -> str:
    """Escape control/bidi characters so repo-controlled text can't forge output lines."""
    return CTRL_RE.sub(lambda m: f"\\u{ord(m.group()):04x}", str(text))


def out(line=""):
    print(safe(line))


def lang_of(path: str):
    return LANG.get(Path(path).suffix.lower())


def is_test(path: str) -> bool:
    return bool(TEST_RE.search(path))


def module_stem(path: str) -> str:
    p = Path(path)
    if p.name in ("__init__.py", "mod.rs", "lib.rs") or p.stem == "index" or p.suffix == ".go":
        return p.parent.name or p.stem
    return p.stem


def capped(items, limit):
    items = list(items)
    s = ", ".join(items[:limit])
    return s + (f" (+{len(items) - limit})" if len(items) > limit else "") if items else "-"


def walk_files(root: Path):
    out = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
        for f in fns:
            out.append((Path(dp) / f).relative_to(root).as_posix())
            if len(out) >= MAX_WALK_FILES:
                return out
    return out


def list_files(root: Path, git_ok: bool):
    """File names only (no content) for name-based test matching."""
    if git_ok:
        r = git(["ls-files", "-co", "--exclude-standard", "-z"], root)
        return [f for f in r.stdout.split("\0") if f]
    return walk_files(root)


def grep_files(root: Path, words, git_ok: bool, src_only=True):
    """Files containing any of the whole words. Targeted: git grep or a capped walk."""
    words = [w for w in words if w]
    if not words:
        return set()
    if git_ok:
        args = ["grep", "-l", "-I", "-w", "-F", "--untracked"]
        for w in words:
            args += ["-e", w]
        if src_only:
            args += ["--"] + [f"*{e}" for e in sorted(SRC_EXT)]
        r = git(args, root)
        return {f for f in r.stdout.splitlines() if f}
    pat = re.compile(r"\b(" + "|".join(map(re.escape, words)) + r")\b")
    hits = set()
    for f in walk_files(root):
        if src_only and Path(f).suffix.lower() not in SRC_EXT:
            continue
        if pat.search(read_text(root, f)):
            hits.add(f)
    return hits


def symbols(lines, lang):
    out = {}
    for line in lines:
        for pat in SYM_PATTERNS.get(lang, []):
            m = pat.match(line)
            if m and m.group(1) not in out:
                out[m.group(1)] = " ".join(line.split())[:120]
    return out


# ---------------------------------------------------------------- scope
def imports_target(text: str, stem: str) -> bool:
    word = re.compile(rf"\b{re.escape(stem)}\b")
    quoted = re.compile(rf"[\"'][^\"']*/{re.escape(stem)}(?:\.\w+)?[\"']")
    for line in text.splitlines():
        if word.search(line) and (IMPORT_KW.search(line) or quoted.search(line)):
            return True
    return False


def risk_of(path, exists, deps, tests, public):
    pts, why = 0, []
    if not exists:
        return "LOW", ["new file"]
    n = len(deps)
    if n:
        pts += 1 if n <= 3 else 2 if n <= 10 else 3
        nt = sum(is_test(d) for d in deps)
        why.append(f"imported by {n} file{'s' if n > 1 else ''}" + (f" ({nt} test)" if nt else ""))
    if public and deps:
        pts += 1
        why.append("public API used elsewhere")
    for pat, label in SENSITIVE:
        if re.search(pat, path, re.I):
            pts += 2
            why.append(label)
            break
    if not tests and not is_test(path):
        pts += 1
        why.append("no related tests")
    return ("LOW" if pts <= 1 else "MEDIUM" if pts <= 3 else "HIGH"), why or ["isolated"]


def analyze_target(root, path, all_files, git_ok):
    full = root / path
    exists = full.is_file()
    stem = module_stem(path)
    text = read_text(root, path) if exists else ""
    lang = lang_of(path)
    public = sorted(symbols(text.splitlines(), lang)) if lang else []
    cands = sorted(grep_files(root, [stem], git_ok) - {path})[:MAX_CANDIDATES]
    deps = [c for c in cands if imports_target(read_text(root, c), stem)]
    tests = {d for d in deps if is_test(d)}
    stem_l = stem.lower()
    tests |= {f for f in all_files if f != path and is_test(f) and stem_l in Path(f).name.lower()
              and Path(f).suffix.lower() in SRC_EXT}
    level, why = risk_of(path, exists, deps, tests, public)
    return {"path": path, "exists": exists, "risk": level, "why": why,
            "dependents": [d for d in deps if d not in tests], "tests": sorted(tests),
            "public": public}


def dirty_snapshot(root, git_ok, head):
    if not git_ok:
        return {}
    names = set(git(["diff", "--name-only", "-z", head or EMPTY_TREE], root).stdout.split("\0"))
    names |= set(git(["ls-files", "-o", "--exclude-standard", "-z"], root).stdout.split("\0"))
    return {n: sha1(root, n) for n in sorted(names) if n}


def cmd_scope(a):
    root = find_root(a.root)
    git_ok = is_git(root)
    sd = state_dir(root)
    prev = load_json(sd / "scope.json") if a.append else None
    targets = list(dict.fromkeys(rel(root, p) for p in a.paths))
    all_files = list_files(root, git_ok)
    infos = [analyze_target(root, t, all_files, git_ok) for t in targets]
    sym_refs = {}
    for s in a.symbol or []:
        sym_refs[s] = sorted(grep_files(root, [s], git_ok) - set(targets))
    if prev:
        known = {i["path"] for i in infos}
        infos = [i for i in prev["targets"] if i["path"] not in known] + infos
        sym_refs = {**prev.get("symbols", {}), **sym_refs}
        head, dirty = prev.get("base"), prev.get("preexisting", {})
    else:
        r = git(["rev-parse", "HEAD"], root) if git_ok else None
        head = r.stdout.strip() if r is not None and r.returncode == 0 else None
        dirty = dirty_snapshot(root, git_ok, head)
    overall = min((i["risk"] for i in infos), key=lambda r: ["HIGH", "MEDIUM", "LOW"].index(r))
    state = {"created": int(time.time()), "base": head, "git": git_ok,
             "allowed": [i["path"] for i in infos], "targets": infos, "symbols": sym_refs,
             "tests": sorted({t for i in infos for t in i["tests"]}), "preexisting": dirty,
             "overall": overall}
    save_json(sd / "scope.json", state)
    if a.json:
        print(json.dumps(state, indent=1))
        return 0
    L = a.limit
    out(f"ChangeGuard scope | base {head[:8] if head else 'none (no git/commits)'} | "
          f"{len(dirty)} pre-existing dirty file(s) ignored")
    for i in infos:
        out(f"[{i['risk']}] {i['path']}{'' if i['exists'] else ' (new)'}  deps={len(i['dependents'])} "
              f"tests={len(i['tests'])} public={len(i['public'])}")
        out(f"  why: {'; '.join(i['why'])}")
        if i["dependents"]:
            out(f"  deps: {capped(i['dependents'], L)}")
        if i["tests"]:
            out(f"  tests: {capped(i['tests'], L)}")
        if i["public"]:
            out(f"  public: {capped(i['public'], L)}")
    for s, refs in sym_refs.items():
        out(f"symbol {s}: referenced in {len(refs)} file(s): {capped(refs, L)}")
    out(f"Overall: {overall}. Allowed scope: {len(infos)} file(s). "
          f"Extend with: scope --append FILE")
    return 0


# ---------------------------------------------------------------- check
def parse_z_pairs(out, numstat=False):
    """Parse `git diff -z --name-status|--numstat` into {path: value}."""
    toks, res, i = out.split("\0"), {}, 0
    while i < len(toks):
        t = toks[i]
        if not t:
            i += 1
            continue
        if numstat:
            parts = t.split("\t")
            if len(parts) == 3 and parts[2] == "":
                res[toks[i + 2]] = (parts[0], parts[1], toks[i + 1])
                i += 3
            else:
                res[parts[2]] = (parts[0], parts[1], None)
                i += 1
        else:
            if t[0] in "RC":
                res[toks[i + 2]] = (t[0], toks[i + 1])
                i += 3
            else:
                res[toks[i + 1]] = (t[0], None)
                i += 2
    return res


def parse_unified(diff_text):
    files, cur = {}, None
    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            cur = None
        elif line.startswith("--- "):
            old = line[4:]
            cur = old[2:] if old.startswith("a/") else None
        elif line.startswith("+++ "):
            new = line[4:]
            if new.startswith("b/"):
                cur = new[2:]
            files.setdefault(cur, {"add": [], "rem": []})
        elif cur is not None and line[:1] in "+-":
            files[cur]["add" if line[0] == "+" else "rem"].append(line[1:])
    return files


def collect_changes(root, base, ignore):
    ns = parse_z_pairs(git(["diff", "--name-status", "-M", "-z", base], root).stdout)
    nums = parse_z_pairs(git(["diff", "--numstat", "-M", "-z", base], root).stdout, numstat=True)
    lines = parse_unified(git(["diff", "-U0", "-M", "--no-color", base], root).stdout)
    changes = {}
    for path, (st, old) in ns.items():
        a_, d_, _ = nums.get(path, ("0", "0", None))
        changes[path] = {"status": st, "old": old, "added": a_, "removed": d_,
                         **lines.get(path, {"add": [], "rem": []})}
    for path in git(["ls-files", "-o", "--exclude-standard", "-z"], root).stdout.split("\0"):
        if path and path not in changes:
            body = read_text(root, path).splitlines()
            changes[path] = {"status": "A", "old": None, "added": str(len(body)), "removed": "0",
                             "add": body, "rem": []}
    return {p: c for p, c in changes.items()
            if ignore.get(p) != sha1(root, p) and not is_generated(p)}


def is_generated(path: str) -> bool:
    parts = path.split("/")
    return Path(path).suffix.lower() in GENERATED_EXT or any(d in SKIP_DIRS for d in parts[:-1])


def params(sig):
    m = re.search(r"\((.*)\)", sig)
    return [x.strip() for x in m.group(1).split(",") if x.strip()] if m else None


def compatible_extension(old_sig, new_sig):
    """True if new_sig only appends parameters that have defaults."""
    old, new = params(old_sig), params(new_sig)
    if old is None or new is None or len(new) <= len(old) or new[:len(old)] != old:
        return False
    return all("=" in x or x.startswith("*") for x in new[len(old):])


def cmd_check(a):
    root = find_root(a.root)
    if not is_git(root):
        out("ChangeGuard check: NOT RUN - not a git repository (diff inspection needs git).")
        return 3
    scope = load_json(state_dir(root) / "scope.json") or {}
    head = git(["rev-parse", "HEAD"], root)
    base = a.base or scope.get("base") or (head.stdout.strip() if head.returncode == 0 else EMPTY_TREE)
    if git(["rev-parse", "--verify", "-q", base + "^{object}"], root).returncode:
        out(f"ChangeGuard check: base '{base}' not found")
        return 2
    preexisting = scope.get("preexisting", {})
    ignore = {} if a.base else preexisting
    changes = collect_changes(root, base, ignore)
    allowed = set(scope.get("allowed", []))
    findings = []

    def add(sev, path, msg):
        findings.append({"sev": sev, "path": path, "msg": msg})

    if not scope:
        add("LOW", "-", "no scope recorded; out-of-scope detection skipped (run `scope` first)")
    all_added_syms = {}
    for p, c in changes.items():
        lg = lang_of(p)
        if lg:
            for s in symbols(c["add"], lg):
                all_added_syms.setdefault(s, p)
    changed = set(changes)
    for p, c in sorted(changes.items()):
        st, lg, test = c["status"], lang_of(p), is_test(p)
        if scope and p not in allowed and (c["old"] or p) not in allowed:
            if p in preexisting or (c["old"] or "") in preexisting:
                add("MED", p, "outside planned scope; had uncommitted edits before scope - "
                              "may contain user work, do not revert")
            else:
                add("MED", p, "outside planned scope")
        for pat, label in SENSITIVE[:4]:
            if re.search(pat, p, re.I):
                add("MED", p, f"{label} changed")
                break
        if st == "D":
            add("HIGH" if test else "MED", p, "test file deleted" if test else "file deleted")
        if lg:
            rem, new = symbols(c["rem"], lg), symbols(c["add"], lg)
            for name, sig in rem.items():
                refs = sorted(grep_files(root, [name], True) - {p})
                if name not in new:
                    if name in all_added_syms and all_added_syms[name] != p:
                        add("MED", p, f"`{name}` moved to {all_added_syms[name]}")
                    elif refs:
                        add("HIGH", p, f"removed public `{name}` still referenced in: {capped(refs, a.limit)}")
                    elif not test:
                        add("MED", p, f"removed public `{name}` (no in-repo references; external users?)")
                elif " ".join(sig.split()) != " ".join(new[name].split()):
                    stale = [r for r in refs if r not in changed]
                    tail = f"; unmodified references: {capped(stale, a.limit)}" if stale else ""
                    if compatible_extension(sig, new[name]):
                        add("LOW", p, f"`{name}` gained optional params (looks backward compatible)")
                    else:
                        add("HIGH" if stale and not test else "MED", p,
                            f"signature changed `{sig}` -> `{new[name]}`{tail}")
        if test:
            lost = sum(bool(ASSERT_RE.search(l)) for l in c["rem"]) - \
                sum(bool(ASSERT_RE.search(l)) for l in c["add"])
            if lost > 0:
                add("HIGH", p, f"test weakened: {lost} net assertion line(s) removed")
            if any(SKIP_MARK.search(l) for l in c["add"]):
                add("HIGH", p, "skip/only marker added")
        for l in c["add"]:
            if CONFLICT_RE.match(l):
                add("HIGH", p, "merge conflict marker")
                break
        if any(SECRET_RE.search(l) for l in c["add"]):
            add("HIGH", p, "possible hard-coded secret")
        dbg = [l.strip() for l in c["add"] if DEBUG_RE.search(l)]
        if dbg:
            add("LOW", p, f"debug leftover: {dbg[0][:60]}")
    total = sum(int(c["added"]) + int(c["removed"]) for c in changes.values()
                if c["added"].isdigit() and c["removed"].isdigit())
    if total > a.max_lines:
        add("LOW", "-", f"large diff: {total} changed lines (> {a.max_lines})")
    findings.sort(key=lambda f: (SEV_ORDER[f["sev"]], f["path"]))
    counts = {s: sum(f["sev"] == s for f in findings) for s in SEV_ORDER}
    result = {"base": base, "files": {p: {k: c[k] for k in ("status", "old", "added", "removed")}
                                      for p, c in changes.items()},
              "findings": findings, "counts": counts,
              "untouched_scope": sorted(allowed - changed)}
    save_json(state_dir(root) / "check.json", result)
    if a.json:
        print(json.dumps(result, indent=1))
    else:
        out(f"ChangeGuard diff vs {base[:8]}: {len(changes)} file(s), {total} changed lines")
        for p, c in sorted(changes.items())[: a.limit * 3]:
            ren = f" (from {c['old']})" if c["old"] else ""
            out(f"  {c['status']} {p}{ren} +{c['added']} -{c['removed']}")
        if len(changes) > a.limit * 3:
            out(f"  ... +{len(changes) - a.limit * 3} more (use --json)")
        if result["untouched_scope"]:
            out(f"  planned but unchanged: {capped(result['untouched_scope'], a.limit)}")
        out("Findings:" if findings else "Findings: none")
        for f in findings:
            out(f"  {f['sev']:<4} {f['path']}: {f['msg']}")
        out(f"Result: {counts['HIGH']} HIGH, {counts['MED']} MED, {counts['LOW']} LOW")
    return 1 if counts["HIGH"] else 0


# ---------------------------------------------------------------- test
def detect_runner(root: Path, files):
    exts = {Path(f).suffix for f in files}
    py_project = any((root / n).exists() for n in
                     ("pyproject.toml", "setup.py", "setup.cfg", "pytest.ini", "tox.ini", "conftest.py"))
    if (files and exts <= {".py"}) or (not files and py_project):
        return "pytest" if importlib.util.find_spec("pytest") else "unittest"
    if (files and exts <= {".go"}) or (not files and (root / "go.mod").exists()):
        return "go"
    if (root / "package.json").exists():
        return "npm"
    return None


def safe_relpath(p: str) -> bool:
    parts = p.split("/")
    return bool(p) and not p.startswith("/") and ".." not in parts and "\0" not in p


def build_cmd(runner, files):
    py = sys.executable
    files = ["./" + f for f in files]  # "./" prefix: a file named "--opt" can't become an option
    if runner == "pytest":
        return [py, "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider", *files]
    if runner == "unittest":
        return [py, "-m", "unittest", "-v", *files]
    if runner == "go":
        dirs = {Path(f).parent.as_posix() for f in files}
        return ["go", "test", "-v", *(sorted(d if d == "." else "./" + d for d in dirs) or ["./..."])]
    if runner == "npm":
        return ["npm", "test", "--silent", *(["--", *files] if files else [])]
    return None


def parse_results(runner, out):
    res = {}
    norm = {"PASSED": "passed", "XPASS": "passed", "XFAIL": "skipped", "FAILED": "failed",
            "ERROR": "error", "ok": "passed", "FAIL": "failed", "PASS": "passed", "SKIP": "skipped",
            "expected failure": "skipped", "unexpected success": "failed"}
    for line in out.splitlines():
        if runner == "pytest":
            m = re.match(r"^(PASSED|FAILED|ERROR|XPASS|XFAIL)\s+(\S+)", line)
            if m:
                res[m.group(2)] = norm[m.group(1)]
        elif runner == "unittest":
            m = re.match(r"^(\w+) \(([^)]+)\).*?\.\.\. (ok|FAIL|ERROR|skipped|expected failure|"
                         r"unexpected success)", line)
            if m:
                name, where = m.group(1), m.group(2)
                tid = where if where.endswith("." + name) else f"{where}.{name}"
                res[tid] = norm.get(m.group(3), "skipped")
        elif runner == "go":
            m = re.match(r"^\s*--- (PASS|FAIL|SKIP): (\S+)", line)
            if m:
                res[m.group(2)] = norm[m.group(1)]
    return res


def summarize(tests):
    c = {"passed": 0, "failed": 0, "error": 0, "skipped": 0}
    for o in tests.values():
        c[o] = c.get(o, 0) + 1
    return c


def cmd_test(a):
    if a.compare is not None and a.compare == a.label:
        out(f"changeguard test: --label and --compare are both {a.label!r}; "
              "use different labels (e.g. --label after --compare before)")
        return 2
    root = find_root(a.root)
    sd = state_dir(root)
    scope = load_json(sd / "scope.json") or {}
    scoped = [t for t in scope.get("tests", []) if isinstance(t, str) and safe_relpath(t)]
    files = [rel(root, f) for f in a.files] or ([] if a.cmd or a.all else scoped)
    rec = {"label": a.label, "ts": int(time.time()), "files": files}
    why = None
    if a.cmd:
        runner, cmd = "custom", a.cmd
    elif not files and not a.all:
        runner, cmd, why = None, None, "no related tests in scope; pass test files, --all, or --cmd"
    else:
        runner = detect_runner(root, files) if a.runner == "auto" else a.runner
        cmd = build_cmd(runner, files) if runner else None
        why = "no test runner detected; pass --cmd or --runner"
    if cmd is None:
        rec.update(status="NOT_RUN", reason=why)
        save_json(sd / f"tests-{a.label}.json", rec)
        out(f"Tests [{a.label}]: NOT RUN - {why}")
        return 3
    prev = load_json(sd / f"tests-{a.compare}.json") if a.compare else None  # before running code
    shown = cmd if isinstance(cmd, str) else " ".join(cmd)
    t0 = time.time()
    try:
        p = run(cmd, root, timeout=a.timeout, shell=isinstance(cmd, str))
        output, code = (p.stdout or "") + (p.stderr or ""), p.returncode
        status = None
    except subprocess.TimeoutExpired:
        output, code, status = "", None, "TIMEOUT"
    except FileNotFoundError as e:
        output, code, status = str(e), None, "NOT_RUN"
    tests = parse_results(runner, output)
    counts = summarize(tests)
    if status is None:
        no_tests = (runner == "pytest" and code == 5) or re.search(r"^Ran 0 tests|NO TESTS RAN", output, re.M)
        status = ("NO_TESTS" if no_tests else "PASSED" if code == 0 else
                  "FAILED" if counts["failed"] or counts["error"] or runner == "custom" else "ERROR")
    rec.update(status=status, cmd=shown, runner=runner, exit_code=code, tests=tests, counts=counts,
               duration=round(time.time() - t0, 2))
    save_json(sd / f"tests-{a.label}.json", rec)

    cmp_lines, regressed, incomplete = [], False, False
    if a.compare:
        if not prev or prev.get("status") in (None, "NOT_RUN"):
            incomplete = True
            cmp_lines.append(f"vs [{a.compare}]: INCOMPLETE - no usable prior run to compare")
        else:
            pt, bad = prev.get("tests", {}), ("failed", "error")
            if pt and tests:
                regs = sorted(t for t, o in pt.items() if o == "passed" and tests.get(t) in bad)
                newf = sorted(t for t, o in tests.items() if o in bad and t not in pt)
                fixed = sorted(t for t, o in pt.items() if o in bad and tests.get(t) == "passed")
                gone = sorted(t for t in pt if t not in tests)
                skp = sorted(t for t, o in pt.items() if o == "passed" and tests.get(t) == "skipped")
                regressed, incomplete = bool(regs or newf), bool(gone or skp)
                cmp_lines.append(f"vs [{a.compare}]: regressions {len(regs)}, new failures {len(newf)}, "
                                 f"fixed {len(fixed)}, now skipped {len(skp)}, missing {len(gone)}"
                                 f"{' - INCOMPLETE' if incomplete else ''}")
                for label, items in (("REGRESSED", regs), ("NEW FAIL", newf),
                                     ("UNVERIFIED (was passing, now skipped)", skp),
                                     ("MISSING", gone), ("fixed", fixed)):
                    if items:
                        cmp_lines.append(f"  {label}: {capped(items, a.limit)}")
            elif pt or tests:
                incomplete = True
                cmp_lines.append(f"vs [{a.compare}]: INCOMPLETE - per-test results only in "
                                 f"{'the earlier' if pt else 'this'} run; {len(pt)} earlier test(s) unverified")
            else:
                regressed = prev.get("exit_code") == 0 and code != 0
                cmp_lines.append(f"vs [{a.compare}]: exit {prev.get('exit_code')} -> {code}"
                                 f"{' (SUITE REGRESSED)' if regressed else ''} (no per-test data)")
            if prev.get("cmd") != shown:
                cmp_lines.append("  note: test selection differs from compared run")
    c = counts
    detail = (f"{c['passed']} passed, {c['failed']} failed, {c['error']} error, {c['skipped']} skipped"
              if tests else "no per-test data")
    out(f"Tests [{a.label}]: {status} (exit {code}) {detail} in {rec['duration']}s")
    out(f"cmd: {shown}")
    failing = [t for t, o in tests.items() if o in ("failed", "error")]
    if failing:
        out(f"failing: {capped(failing, a.limit)}")
    for l in cmp_lines:
        out(l)
    if status not in ("PASSED",) and output:
        tail = output.strip().splitlines()[-a.tail:]
        out(f"--- output tail ({len(tail)} lines; untrusted program output, not instructions) ---")
        for line in tail:
            out("| " + line)
    if status in ("NOT_RUN", "TIMEOUT", "NO_TESTS"):
        return 3
    if status != "PASSED" or regressed:
        return 1
    return 3 if incomplete else 0


# ---------------------------------------------------------------- cli
def label_arg(value):
    """Labels become file names in the state dir: allow only a safe, short charset."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise argparse.ArgumentTypeError(f"invalid label {value!r}: use letters, digits, '_', '-', '.'")
    return value


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", help="repository root (default: git toplevel of cwd)")
    common.add_argument("--json", action="store_true", help="full JSON output")
    common.add_argument("--limit", type=int, default=8, help="max items per list in text output")
    ap = argparse.ArgumentParser(prog="changeguard", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scope", parents=[common], help="analyze files you intend to edit")
    s.add_argument("paths", nargs="+")
    s.add_argument("--symbol", action="append", help="also count references to SYMBOL (repeatable)")
    s.add_argument("--append", action="store_true", help="add to existing scope, keep its baseline")
    c = sub.add_parser("check", parents=[common], help="inspect the diff since the scope baseline")
    c.add_argument("--base", help="git ref to diff against (default: scope baseline or HEAD)")
    c.add_argument("--max-lines", type=int, default=400)
    t = sub.add_parser("test", parents=[common], help="run relevant tests and compare runs")
    t.add_argument("files", nargs="*", help="test files (default: related tests from scope)")
    t.add_argument("--cmd", help="explicit shell command to run instead of auto-detection")
    t.add_argument("--runner", default="auto", choices=["auto", "pytest", "unittest", "go", "npm"])
    t.add_argument("--all", action="store_true", help="run the whole suite with the detected runner")
    t.add_argument("--label", default="after", type=label_arg)
    t.add_argument("--compare", type=label_arg, help="label of a previous run to diff against (e.g. before)")
    t.add_argument("--timeout", type=int, default=600)
    t.add_argument("--tail", type=int, default=25, help="output lines shown on failure")
    a = ap.parse_args(argv)
    return {"scope": cmd_scope, "check": cmd_check, "test": cmd_test}[a.command](a)


if __name__ == "__main__":
    sys.exit(main())
