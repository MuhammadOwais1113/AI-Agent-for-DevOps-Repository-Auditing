"""Read-only inspection tools for the DevOps auditing agent.

Every tool takes a ``RepoContext`` (the locally cloned, never-executed target)
and returns a plain string that the LLM interprets. Tools never modify the
repository and never execute code that belongs to it.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

MAX_OUTPUT_CHARS = 8000
MAX_FILE_BYTES = 200_000
MAX_SEARCH_RESULTS = 60
MAX_LIST_ENTRIES = 400
GIT_TIMEOUT = 60
CLONE_TIMEOUT = 180

SKIP_DIRS = {".git"}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".whl",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pyc", ".so", ".dll", ".exe",
    ".bin", ".pkl", ".parquet", ".npy", ".jar", ".class", ".svg", ".webp",
}

# (label, regex). Used to redact before anything reaches the LLM, logs or report.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("url_credentials", re.compile(r"://[^/\s:@]+:[^/\s:@]{3,}@")),
]
# key = "literal value" style assignments
ASSIGNMENT_SECRET = re.compile(
    r"""(?ix)
    (?P<key>[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|
        auth[_-]?token|token|private[_-]?key|client[_-]?secret)[\w.-]*)
    (?P<sep>\s*[:=]\s*)
    (?P<quote>["'])(?P<val>[^"'\s]{6,})(?P=quote)
    """
)
PLACEHOLDER_HINT = re.compile(
    r"(?i)(example|placeholder|changeme|change_me|your[_-]|<.*>|\$\{|\{\{|xxx+|\*\*\*|dummy|sample|todo|none|null|env\b|getenv|environ)"
)


def redact(text: str) -> str:
    """Mask secret-looking values so they never reach the LLM, logs or report."""
    for label, pat in SECRET_PATTERNS:
        text = pat.sub(f"[REDACTED:{label}]", text)

    def _assign(m: re.Match) -> str:
        if PLACEHOLDER_HINT.search(m.group("val")):
            return m.group(0)
        return f"{m.group('key')}{m.group('sep')}{m.group('quote')}[REDACTED:literal_secret]{m.group('quote')}"

    return ASSIGNMENT_SECRET.sub(_assign, text)


def truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"


class ToolError(Exception):
    """Raised for bad arguments / unavailable checks; message goes back to the LLM."""


@dataclass
class RepoContext:
    root: Path
    url: str = ""
    _files: list[str] | None = field(default=None, repr=False)

    def all_files(self) -> list[str]:
        if self._files is None:
            out = []
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for fn in filenames:
                    rel = Path(dirpath, fn).relative_to(self.root).as_posix()
                    out.append(rel)
            self._files = sorted(out)
        return self._files

    def resolve(self, rel: str) -> Path:
        """Resolve a repo-relative path, refusing escapes (.. / absolute / symlinks)."""
        if not isinstance(rel, str) or not rel.strip():
            raise ToolError("path must be a non-empty string")
        p = (self.root / rel.strip().lstrip("/\\")).resolve()
        try:
            p.relative_to(self.root.resolve())
        except ValueError:
            raise ToolError(f"path escapes repository: {rel}")
        return p


def _git(ctx: RepoContext, *args: str, timeout: int = GIT_TIMEOUT) -> str:
    if shutil.which("git") is None:
        raise ToolError("git executable not available")
    try:
        r = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", str(ctx.root), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ToolError("git command timed out")
    if r.returncode != 0:
        raise ToolError(f"git failed: {r.stderr.strip()[:300]}")
    return r.stdout


# ---------------------------------------------------------------- cloning


GITHUB_URL = re.compile(r"^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def normalize_repo_url(url: str) -> str:
    m = GITHUB_URL.match((url or "").strip())
    if not m:
        raise ValueError(f"not a valid public GitHub repository URL: {url!r}")
    return f"https://github.com/{m.group(1)}/{m.group(2)}"


def clone_repo(url: str, dest: str | None = None, depth: int = 200) -> RepoContext:
    """Shallow-clone a public repo with hooks/filters disabled. Nothing is executed."""
    clean = normalize_repo_url(url)
    if shutil.which("git") is None:
        raise RuntimeError("git is required but was not found on PATH")
    dest = dest or tempfile.mkdtemp(prefix="audit_")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    cmd = [
        "git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
        "-c", "protocol.file.allow=never",
        "clone", "--quiet", "--depth", str(depth), "--no-tags", clean + ".git", dest,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=env,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"timed out cloning {clean}")
    if r.returncode != 0:
        raise RuntimeError(f"could not clone {clean}: {r.stderr.strip()[:300]}")
    return RepoContext(root=Path(dest), url=clean)


# ---------------------------------------------------------------- tools


def list_files(ctx: RepoContext, directory: str = "", max_depth: int | None = None) -> str:
    """List files (git-tracked, relative paths) with sizes, optionally under a directory."""
    directory = (directory or "").strip().strip("/")
    files = ctx.all_files()
    if directory:
        files = [f for f in files if f == directory or f.startswith(directory + "/")]
    if max_depth is not None:
        base = directory.count("/") + 1 if directory else 0
        files = [f for f in files if f.count("/") - base < int(max_depth)]
    if not files:
        return f"No files found under '{directory or '.'}'."
    lines = []
    for f in files[:MAX_LIST_ENTRIES]:
        try:
            size = (ctx.root / f).stat().st_size
        except OSError:
            size = -1
        lines.append(f"{f}  ({size}B)")
    extra = f"\n... {len(files) - MAX_LIST_ENTRIES} more files not shown; pass a directory to narrow." \
        if len(files) > MAX_LIST_ENTRIES else ""
    return f"{len(files)} files:\n" + "\n".join(lines) + extra


def read_file(ctx: RepoContext, path: str, start_line: int = 1, end_line: int | None = None) -> str:
    """Read a text file with line numbers; secrets are redacted."""
    p = ctx.resolve(path)
    if not p.exists():
        raise ToolError(f"file not found: {path}")
    if p.is_dir():
        raise ToolError(f"{path} is a directory; use list_files")
    if p.suffix.lower() in BINARY_EXT:
        return f"{path}: binary/non-text file ({p.stat().st_size} bytes), not shown."
    data = p.read_bytes()[:MAX_FILE_BYTES]
    if b"\x00" in data[:2048]:
        return f"{path}: binary file, not shown."
    lines = data.decode("utf-8", errors="replace").splitlines()
    s = max(int(start_line or 1), 1)
    e = min(int(end_line), len(lines)) if end_line else len(lines)
    body = "\n".join(f"{i}: {redact(lines[i - 1])}" for i in range(s, e + 1))
    header = f"=== {path} (lines {s}-{e} of {len(lines)}) ===\n"
    return truncate(header + body)


def search_code(ctx: RepoContext, pattern: str, glob: str = "", ignore_case: bool = True) -> str:
    """Regex search across text files. Returns path:line: text (redacted)."""
    if not pattern:
        raise ToolError("pattern must be non-empty")
    try:
        rx = re.compile(pattern, re.I if ignore_case else 0)
    except re.error as e:
        raise ToolError(f"invalid regex: {e}")
    hits: list[str] = []
    total = 0
    for rel in ctx.all_files():
        if glob and not (fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(Path(rel).name, glob)):
            continue
        if Path(rel).suffix.lower() in BINARY_EXT:
            continue
        p = ctx.root / rel
        try:
            if p.stat().st_size > MAX_FILE_BYTES or p.is_symlink():
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                total += 1
                if len(hits) < MAX_SEARCH_RESULTS:
                    hits.append(f"{rel}:{i}: {redact(line.strip())[:200]}")
    if not hits:
        return f"No matches for /{pattern}/" + (f" in {glob}" if glob else "")
    more = f"\n... {total - len(hits)} more matches" if total > len(hits) else ""
    return f"{total} matches:\n" + "\n".join(hits) + more


def git_log(ctx: RepoContext, max_count: int = 30, path: str = "") -> str:
    """Recent commit history (hash, author date, subject), optionally for one path."""
    max_count = max(1, min(int(max_count or 30), 100))
    args = ["log", f"--max-count={max_count}", "--date=short", "--pretty=format:%h | %ad | %an | %s"]
    if path:
        ctx.resolve(path)
        args += ["--", path]
    out = _git(ctx, *args)
    if not out.strip():
        return "No commits found."
    try:
        total = _git(ctx, "rev-list", "--count", "HEAD").strip()
    except ToolError:
        total = "?"
    shallow = (ctx.root / ".git" / "shallow").exists()
    note = " (history is shallow-cloned; older commits omitted)" if shallow else ""
    return f"commits in available history: {total}{note}\n" + out


def git_status(ctx: RepoContext) -> str:
    """Tracked files that look generated/temporary/local, plus overall tracking stats."""
    tracked = _git(ctx, "ls-files").splitlines()
    patterns = [
        "*.pyc", "__pycache__/*", "*/__pycache__/*", ".env", "*.env", ".DS_Store", "*.log", "*.sqlite",
        "*.sqlite3", "*.db", "node_modules/*", "venv/*", ".venv/*", "env/*", ".idea/*", ".vscode/*",
        "dist/*", "build/*", "*.egg-info/*", ".pytest_cache/*", ".coverage", "htmlcov/*", "*.swp",
        "*.tmp", "*.bak", "*.pem", "*.key", "id_rsa*", "Thumbs.db", ".mypy_cache/*", ".ruff_cache/*",
    ]
    flagged = sorted({f for f in tracked for pat in patterns
                      if (fnmatch.fnmatch(f, pat) or fnmatch.fnmatch(Path(f).name, pat))
                      and not f.endswith((".env.example", ".env.sample", ".env.template"))})
    gitignore = ctx.root / ".gitignore"
    gi = "present" if gitignore.exists() else "ABSENT"
    out = [f"tracked files: {len(tracked)}", f".gitignore: {gi}"]
    if flagged:
        out.append("tracked files matching generated/temporary/local patterns:")
        out += [f"  {f}" for f in flagged[:80]]
    else:
        out.append("no tracked files match common generated/temporary/local patterns")
    return "\n".join(out)


def run_ruff(ctx: RepoContext, path: str = ".") -> str:
    """Static lint with ruff (no code from the repo is executed; repo ruff config is ignored)."""
    exe = shutil.which("ruff")
    if exe is None:
        raise ToolError("ruff is not installed in the auditor's environment; check unavailable")
    ctx.resolve(path)
    try:
        r = subprocess.run(
            [exe, "check", "--isolated", "--no-cache", "--select", "E9,F63,F7,F82,F401,F841",
             "--output-format", "concise", path],
            cwd=ctx.root, capture_output=True, text=True, timeout=90, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        raise ToolError("ruff timed out")
    out = (r.stdout or r.stderr).strip()
    return truncate(out) if out else "ruff: no issues found with the selected rule set"


def inspect_workflow(ctx: RepoContext, path: str) -> str:
    """Summarise a GitHub Actions workflow: triggers, permissions, steps, risky constructs."""
    p = ctx.resolve(path)
    if not p.exists():
        raise ToolError(f"file not found: {path}")
    text = p.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    findings: list[str] = []

    def add(rx: str, msg: str, flags: int = 0) -> None:
        for i, ln in enumerate(lines, 1):
            if ln.lstrip().startswith("#"):
                continue
            if re.search(rx, ln, flags):
                findings.append(f"line {i}: {msg}: {redact(ln.strip())[:160]}")

    add(r"^\s*on:|^\s*['\"]?on['\"]?:", "trigger block")
    add(r"pull_request_target", "pull_request_target trigger (runs with secrets/write token on untrusted PRs)")
    add(r"workflow_run", "workflow_run trigger")
    add(r"permissions:\s*write-all|:\s*write-all", "write-all permissions")
    add(r"^\s*(contents|packages|id-token|pull-requests|actions|issues|deployments):\s*write", "write permission scope")
    add(r"^\s*permissions:", "permissions block")
    add(r"uses:\s*[\w./-]+@(main|master|latest|dev|HEAD)\b", "action pinned to mutable branch")
    add(r"uses:\s*[\w./-]+@[0-9a-f]{40}\b", "action pinned to full commit SHA (GOOD practice, not a defect)")
    add(r"uses:\s*[\w./-]+@(?![0-9a-f]{40}\b)v?\d[\w.]*\s*(#.*)?$", "action pinned to version tag (mutable; lower risk than a branch)")
    add(r"uses:\s*(?!\./)[\w./-]+\s*(#.*)?$", "action with no version pin")
    add(r"continue-on-error:\s*true", "continue-on-error: true (failures ignored)")
    add(r"\|\|\s*(true|exit 0)", "'|| true' swallows failures")
    add(r"^\s*if:\s*(false|\$\{\{\s*false\s*\}\})", "step/job disabled via if: false")
    add(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|head_commit|review)[\w.]*(title|body|message|ref|label|name)", "untrusted event data interpolated (script injection risk)")
    add(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", "checks out/uses PR head ref")
    add(r"actions/checkout", "checkout step")
    add(r"persist-credentials:\s*true", "persist-credentials enabled")
    add(r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba)?sh", "pipe-to-shell download")
    add(r"echo\s+.*\$\{\{\s*secrets\.", "secret echoed in run step")
    add(r"\b(pytest|unittest|tox|nox|npm (run )?test|go test|cargo test|mvn test|gradle test|make test)\b", "test execution")
    add(r"\b(ruff|flake8|pylint|black|isort|mypy|eslint|golangci-lint)\b", "lint/format/type step")
    add(r"\b(docker (build|push)|twine upload|pypi|npm publish|gh release|deploy|kubectl|terraform apply|aws s3 sync)\b", "build/release/deploy step")
    add(r"runs-on:\s*self-hosted", "self-hosted runner")
    add(r"timeout-minutes:", "timeout configured")
    add(r"concurrency:", "concurrency configured")
    summary = "\n".join(findings) if findings else "no notable constructs matched"
    return truncate(f"=== workflow analysis: {path} ({len(lines)} lines) ===\n{summary}\n"
                    f"(use read_file to confirm any finding in context before reporting it)")


def scan_secrets(ctx: RepoContext, glob: str = "") -> str:
    """Scan all text files for credential-shaped values. Never prints the values."""
    results: list[str] = []
    for rel in ctx.all_files():
        if glob and not (fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(Path(rel).name, glob)):
            continue
        if Path(rel).suffix.lower() in BINARY_EXT:
            continue
        p = ctx.root / rel
        try:
            if p.stat().st_size > MAX_FILE_BYTES or p.is_symlink():
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for label, pat in SECRET_PATTERNS:
                if pat.search(line):
                    results.append(f"{rel}:{i}: {label}")
            m = ASSIGNMENT_SECRET.search(line)
            if m and not PLACEHOLDER_HINT.search(m.group("val")) and not PLACEHOLDER_HINT.search(line):
                results.append(f"{rel}:{i}: literal value assigned to '{m.group('key')}'")
    if not results:
        return "No credential-shaped values found (heuristic scan; values are never shown)."
    results = list(dict.fromkeys(results))
    return truncate(f"{len(results)} candidate secrets (verify context with read_file; values withheld):\n"
                    + "\n".join(results[:MAX_SEARCH_RESULTS]))


# name -> (callable, description shown to the LLM)
TOOLS: dict[str, tuple[Callable[..., str], str]] = {
    "list_files": (list_files, 'list_files(directory="", max_depth=null) - list repo files with sizes; narrow by directory.'),
    "read_file": (read_file, 'read_file(path, start_line=1, end_line=null) - read a file with line numbers (secrets redacted).'),
    "search_code": (search_code, 'search_code(pattern, glob="", ignore_case=true) - regex search; returns path:line: text.'),
    "git_log": (git_log, 'git_log(max_count=30, path="") - recent commit history.'),
    "git_status": (git_status, "git_status() - tracked files that look generated/temporary/local, .gitignore presence."),
    "run_ruff": (run_ruff, 'run_ruff(path=".") - static lint for real errors/dead code (may be unavailable).'),
    "inspect_workflow": (inspect_workflow, "inspect_workflow(path) - structured summary of risky/key constructs in a GitHub Actions workflow."),
    "scan_secrets": (scan_secrets, 'scan_secrets(glob="") - heuristic credential scan; reports locations only, never values.'),
}


def execute_tool(ctx: RepoContext, name: str, args: dict | None) -> str:
    """Dispatch a tool call; always returns a string (errors are reported, not raised)."""
    if name not in TOOLS:
        return f"ERROR: unknown tool '{name}'. Available: {', '.join(TOOLS)}"
    fn = TOOLS[name][0]
    try:
        return fn(ctx, **(args or {}))
    except ToolError as e:
        return f"ERROR: {e}"
    except TypeError as e:
        return f"ERROR: bad arguments for {name}: {e}"
    except Exception as e:  # tools must never crash the agent loop
        return f"ERROR: {name} failed: {type(e).__name__}: {e}"
