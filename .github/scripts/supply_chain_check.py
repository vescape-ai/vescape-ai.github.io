#!/usr/bin/env python3
"""Supply-chain gate, one script for every vescape-ai repo (box factory/plan.md 3e, fp#40 generalised).

Canonical copy: vescape-ai/box ci/supply_chain_check.py. Other repos vendor it byte-for-byte as
.github/scripts/supply_chain_check.py (stdlib only, Python 3.11+). Rules:

  action-sha     every workflow `uses:` is a 40-hex commit SHA (./local and docker://...@sha256 allowed)
  image-digest   Dockerfile FROM, compose/workflow `image:`/`container:` and literal `--image` end in @sha256:<64 hex>
  npm-exact      package.json dependencies/devDependencies/optionalDependencies are exact versions
  npm-lock       package-lock.json next to every package.json and its root specs/versions match
  npm-install    no `npm install`/`npm i`/`npm add`/`yarn add` in scripts, Dockerfiles or workflows (use `npm ci`)
  ignore-scripts `npm ci` carries --ignore-scripts, and every npm project has .npmrc ignore-scripts=true
  pip-pin        requirements*.txt lines are `name==version`; `pip install` names are pinned or -r files;
                 pyproject.toml with dependencies has uv.lock; `uv sync` uses --frozen or --locked
  dependabot     .github/dependabot.yml covers each ecosystem in use, each entry with cooldown default-days >= 3

Exceptions: .github/supply-chain-allow.txt, one per line: `<rule> <path glob> -- <reason>` (reason required).
Usage: supply_chain_check.py [repo root]   (exit 1 on any unexcepted finding)
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path

VERSION = "1"
SHA40 = re.compile(r"@[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
EXACT = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
LOCAL_SPEC = ("file:", "link:", "workspace:", "portal:")
DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies")
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__"}
COOLDOWN_DAYS = 3


class Finding:
    def __init__(self, rule: str, path: str, line: int, msg: str):
        self.rule, self.path, self.line, self.msg = rule, path, line, msg

    def __str__(self) -> str:
        return f"FAIL {self.rule} {self.path}:{self.line} {self.msg}"


def tracked_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
        files = [f for f in out.decode().split("\0") if f]
    except (subprocess.CalledProcessError, FileNotFoundError):
        files = []
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            files += [os.path.relpath(os.path.join(dp, f), root) for f in fns]
    return sorted(f for f in files if not (set(Path(f).parts) & SKIP_DIRS) and (root / f).is_file())


def read(root: Path, rel: str) -> str:
    try:
        return (root / rel).read_text(errors="replace")
    except OSError:
        return ""


def logical_lines(text: str):
    """(first line number, joined line) with backslash continuations folded, comments dropped."""
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        yield start, buf
        buf = ""
    if buf:
        yield start, buf


def is_dockerfile(rel: str) -> bool:
    name = Path(rel).name
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile") or name == "Containerfile"


def is_workflow(rel: str) -> bool:
    return rel.startswith((".github/workflows/", ".github/actions/")) and rel.endswith((".yml", ".yaml"))


def is_compose(rel: str) -> bool:
    return re.fullmatch(r"(docker-)?compose[^/]*\.ya?ml", Path(rel).name) is not None


def is_script(rel: str) -> bool:
    return rel.endswith((".sh", ".bash")) or Path(rel).name in {"Makefile", "justfile", "Procfile"}


# ---------------------------------------------------------------- rules

def check_actions(root, rel, text, out):
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*-?\s*uses:\s*(\S+)", line)
        if not m:
            continue
        ref = m.group(1).strip("'\"")
        if ref.startswith("./") or (ref.startswith("docker://") and DIGEST.search(ref)) or SHA40.search(ref):
            continue
        out.append(Finding("action-sha", rel, n, f"`uses: {ref}` is not pinned to a commit SHA"))


def check_dockerfile(root, rel, text, out):
    stages, args = set(), {}
    for n, line in logical_lines(text):
        s = line.strip()
        am = re.match(r"(?i)^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(\S+))?", s)
        if am:
            args[am.group(1)] = (am.group(2) or "").strip("'\"")
            continue
        fm = re.match(r"(?i)^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", s)
        if not fm:
            continue
        image = fm.group(1)
        resolved = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}?", lambda m: args.get(m.group(1), m.group(0)), image)
        if fm.group(2):
            stages.add(fm.group(2).lower())
        if resolved.lower() == "scratch" or resolved.lower() in stages - {(fm.group(2) or "").lower()}:
            continue
        if not DIGEST.search(resolved):
            out.append(Finding("image-digest", rel, n, f"FROM {image} is not pinned by @sha256 digest"))


def check_image_refs(root, rel, text, out):
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*-?\s*(?:image|container):\s*['\"]?([^\s'\"#{}]+)", line)
        if m and "$" not in m.group(1) and not DIGEST.search(m.group(1)):
            out.append(Finding("image-digest", rel, n, f"image {m.group(1)} is not pinned by @sha256 digest"))


def check_image_flags(root, rel, text, out):
    for n, line in logical_lines(text):
        if line.lstrip().startswith("#"):
            continue
        for m in re.finditer(r"--image[= ]+['\"]?([^\s'\"]+)", line):
            ref = m.group(1)
            if "$" in ref or "{{" in ref or DIGEST.search(ref):
                continue
            out.append(Finding("image-digest", rel, n, f"--image {ref} is not pinned by @sha256 digest"))


def check_commands(root, rel, text, out):
    for n, line in logical_lines(text):
        code = line.split(" #", 1)[0] if not is_dockerfile(rel) else line
        if code.lstrip().startswith("#"):
            continue
        code = re.sub(r"\b(echo|printf)\s+(\"(?:[^\"\\\\]|\\\\.)*\"|'[^']*')", r"\1", code)
        for seg in re.split(r"&&|\|\||;|\||\$\(|`", code):
            words = seg.split()
            if words and words[0] in ("echo", "printf", "log", "say", "die", "warn", "info"):
                continue   # text that mentions a command, not a command
            for i, w in enumerate(words):
                nxt = words[i + 1] if i + 1 < len(words) else ""
                if w in ("npm", "pnpm") and nxt in ("install", "i", "add", "isntall"):
                    if global_exact(words[i + 2:]):
                        continue
                    out.append(Finding("npm-install", rel, n, f"`{w} {nxt}` resolves fresh versions; use `npm ci --ignore-scripts`"))
                elif w == "yarn" and nxt in ("add", "install", "") and "--frozen-lockfile" not in words and "--immutable" not in words:
                    out.append(Finding("npm-install", rel, n, "`yarn` without --frozen-lockfile/--immutable"))
                elif w == "npm" and nxt == "ci" and "--ignore-scripts" not in words:
                    out.append(Finding("ignore-scripts", rel, n, "`npm ci` without --ignore-scripts"))
                elif w == "uv" and nxt == "sync" and not ({"--frozen", "--locked"} & set(words)):
                    out.append(Finding("pip-pin", rel, n, "`uv sync` without --frozen/--locked"))
                elif w in ("pip", "pip3") and nxt == "install":
                    check_pip_args(rel, n, words[i + 2:], out)
                elif w == "-m" and nxt == "pip" and i + 2 < len(words) and words[i + 2] == "install":
                    check_pip_args(rel, n, words[i + 3:], out)


def global_exact(args: list[str]) -> bool:
    """`npm install -g name@1.2.3 ...`: a global CLI with exact versions has no lockfile to use."""
    if not ({"-g", "--global"} & set(args)):
        return False
    specs, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a in ("--prefix", "--registry", "--loglevel"):
            skip = True
        elif not a.startswith("-"):
            specs.append(a.strip("'\""))
    return bool(specs) and all(EXACT.match(x.rsplit("@", 1)[-1]) and x.rsplit("@", 1)[0] for x in specs)


def check_pip_args(rel, n, args, out):
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in ("-r", "--requirement", "-c", "--constraint", "--index-url", "-i", "--extra-index-url", "-t", "--target",
                 "--prefix", "--root", "-f", "--find-links", "--python", "--platform", "--only-binary", "--no-binary"):
            skip_next = True
            continue
        a = a.strip("'\"")
        if re.match(r"^\d*(>>?|<)", a):   # a redirect such as 2>/dev/null ends the arguments
            break
        if a.startswith(("-", "$")) or a in (".", ""):
            if a == ".":
                out.append(Finding("pip-pin", rel, n, "`pip install .` resolves the project's ranges; use uv sync --frozen"))
            continue
        if "==" not in a:
            out.append(Finding("pip-pin", rel, n, f"`pip install {a}` is not pinned with =="))


def check_requirements(root, rel, text, out):
    for n, line in logical_lines(text):
        s = line.split("#", 1)[0].strip() if not line.strip().startswith("--hash") else ""
        if not s or s.startswith(("-r", "-c", "--requirement", "--constraint", "--hash", "--index-url", "--extra-index-url", "-i ")):
            continue
        req = s.split(";", 1)[0].split("--hash", 1)[0].strip()
        if not re.match(r"^[A-Za-z0-9._-]+(\[[^\]]*\])?\s*===?\s*[^\s,]+$", req):
            out.append(Finding("pip-pin", rel, n, f"`{req}` is not an exact `==` pin"))


def check_npm_project(root, rel, files_set, out):
    d = str(Path(rel).parent)
    pre = "" if d == "." else d + "/"
    try:
        man = json.loads(read(root, rel))
    except json.JSONDecodeError as e:
        out.append(Finding("npm-exact", rel, 1, f"unparsable package.json: {e.msg}"))
        return
    deps = {}
    for key in DEP_KEYS:
        for name, spec in (man.get(key) or {}).items():
            deps[name] = (key, spec)
            if isinstance(spec, str) and spec.startswith(LOCAL_SPEC):
                continue
            bare = spec.split("@")[-1] if isinstance(spec, str) and spec.startswith("npm:") else spec
            if not (isinstance(bare, str) and EXACT.match(bare)):
                out.append(Finding("npm-exact", rel, 1, f"{key}.{name} '{spec}' is not an exact version"))
    lock_rel = next((pre + f for f in ("package-lock.json", "npm-shrinkwrap.json") if pre + f in files_set), None)
    if deps and not lock_rel:
        out.append(Finding("npm-lock", rel, 1, "no package-lock.json next to package.json"))
    elif lock_rel:
        try:
            lock = json.loads(read(root, lock_rel))
            pkgs = lock.get("packages", {})
            root_pkg = pkgs.get("", {})
            for name, (key, spec) in deps.items():
                if isinstance(spec, str) and spec.startswith(LOCAL_SPEC):
                    continue
                if root_pkg.get(key, {}).get(name) != spec:
                    out.append(Finding("npm-lock", lock_rel, 1, f"root {key}.{name} is {root_pkg.get(key, {}).get(name)!r}, package.json says {spec!r} (run npm install --package-lock-only --ignore-scripts)"))
                ver = pkgs.get("node_modules/" + name, {}).get("version")
                if EXACT.match(str(spec)) and ver != spec:
                    out.append(Finding("npm-lock", lock_rel, 1, f"locked {name} {ver} != {spec}"))
        except json.JSONDecodeError as e:
            out.append(Finding("npm-lock", lock_rel, 1, f"unparsable lockfile: {e.msg}"))
    if deps and not any(ignore_scripts_on(read(root, p)) for p in (pre + ".npmrc", ".npmrc") if p in files_set):
        out.append(Finding("ignore-scripts", rel, 1, f"no .npmrc with ignore-scripts=true in {d} or the repo root"))


def ignore_scripts_on(text: str) -> bool:
    return re.search(r"(?m)^\s*ignore-scripts\s*=\s*true\s*$", text) is not None


def check_pyproject(root, rel, files_set, out):
    try:
        data = tomllib.loads(read(root, rel))
    except tomllib.TOMLDecodeError as e:
        out.append(Finding("pip-pin", rel, 1, f"unparsable pyproject.toml: {e}"))
        return
    deps = (data.get("project") or {}).get("dependencies") or []
    groups = (data.get("dependency-groups") or {})
    if not deps and not groups:
        return
    pre = "" if str(Path(rel).parent) == "." else str(Path(rel).parent) + "/"
    if pre + "uv.lock" not in files_set and "uv.lock" not in files_set:
        out.append(Finding("pip-pin", rel, 1, "pyproject.toml declares dependencies but there is no uv.lock (install with uv sync --frozen)"))


def ecosystems(files: list[str]) -> dict[str, str]:
    need = {}
    for f in files:
        name = Path(f).name
        if is_workflow(f) and f.startswith(".github/workflows/"):
            need.setdefault("github-actions", f)
        elif name == "package.json":
            need.setdefault("npm", f)
        elif re.fullmatch(r"requirements[^/]*\.txt", name):
            need.setdefault("pip", f)
        elif name == "uv.lock":
            need.setdefault("uv", f)
        elif is_dockerfile(f):
            need.setdefault("docker", f)
    if "uv" in need:
        need.pop("pip", None)
    return need


def check_dependabot(root, files, out):
    need = ecosystems(files)
    if not need:
        return
    rel = next((f for f in (".github/dependabot.yml", ".github/dependabot.yaml") if f in files), None)
    if not rel:
        out.append(Finding("dependabot", ".github/dependabot.yml", 0, f"missing; needed for {', '.join(sorted(need))} with cooldown default-days >= {COOLDOWN_DAYS}"))
        return
    text = read(root, rel)
    blocks = re.split(r"(?m)^\s*-\s*package-ecosystem:", text)[1:]
    have = {}
    for b in blocks:
        eco = b.split("\n", 1)[0].strip().strip("'\"")
        m = re.search(r"default-days:\s*(\d+)", b)
        days = int(m.group(1)) if m and re.search(r"cooldown", b) else 0
        have[eco] = max(have.get(eco, 0), days) if eco in have else days
        if days < COOLDOWN_DAYS:
            out.append(Finding("dependabot", rel, 0, f"{eco}: cooldown default-days {days} < {COOLDOWN_DAYS}"))
    alias = {"pip": {"pip", "uv"}, "uv": {"uv", "pip"}}
    for eco, why in sorted(need.items()):
        if not (alias.get(eco, {eco}) & set(have)):
            out.append(Finding("dependabot", rel, 0, f"no `{eco}` entry (needed by {why})"))


# ---------------------------------------------------------------- driver

def load_allow(root: Path, out: list) -> list[tuple[str, str, str]]:
    rel = ".github/supply-chain-allow.txt"
    allow = []
    for n, line in enumerate(read(root, rel).splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^(\S+)\s+(\S+)\s+--\s+(\S.*)$", s)
        if not m:
            out.append(Finding("allowlist", rel, n, "expected `<rule> <path glob> -- <reason>`"))
            continue
        allow.append((m.group(1), m.group(2), m.group(3)))
    return allow


def run(root: Path) -> tuple[list[Finding], list[Finding], list[tuple]]:
    files = tracked_files(root)
    files_set = set(files)
    out: list[Finding] = []
    for rel in files:
        name = Path(rel).name
        text = None
        if is_workflow(rel):
            text = read(root, rel)
            check_actions(root, rel, text, out)
            check_image_refs(root, rel, text, out)
            check_commands(root, rel, text, out)
            check_image_flags(root, rel, text, out)
        elif is_dockerfile(rel):
            text = read(root, rel)
            check_dockerfile(root, rel, text, out)
            check_commands(root, rel, text, out)
        elif is_compose(rel):
            check_image_refs(root, rel, read(root, rel), out)
        elif is_script(rel):
            text = read(root, rel)
            check_commands(root, rel, text, out)
            check_image_flags(root, rel, text, out)
        if name == "package.json":
            check_npm_project(root, rel, files_set, out)
            scripts = (json.loads(read(root, rel) or "{}").get("scripts") or {}) if read(root, rel).strip().startswith("{") else {}
            for v in scripts.values():
                check_commands(root, rel, str(v), out)
        elif re.fullmatch(r"requirements[^/]*\.txt", name):
            check_requirements(root, rel, read(root, rel), out)
        elif name == "pyproject.toml":
            check_pyproject(root, rel, files_set, out)
    check_dependabot(root, files, out)
    seen, uniq = set(), []
    for f in out:
        k = (f.rule, f.path, f.line, f.msg)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    out = uniq
    allow = load_allow(root, out)
    used, failed, excepted = set(), [], []
    for f in out:
        hit = next((a for a in allow if a[0] == f.rule and fnmatch.fnmatch(f.path, a[1])), None)
        if hit:
            used.add(hit)
            excepted.append(f)
        else:
            failed.append(f)
    return failed, excepted, [a for a in allow if a not in used]


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    failed, excepted, unused = run(root)
    for f in failed:
        print(f)
    for f in excepted:
        print(f"EXCEPTED {f.rule} {f.path}:{f.line} {f.msg}")
    for a in unused:
        print(f"WARN unused allowlist entry: {a[0]} {a[1]}")
    print(f"supply-chain v{VERSION}: {len(failed)} violation(s), {len(excepted)} excepted")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
