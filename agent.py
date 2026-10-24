#!/usr/bin/env python3
"""DevOps repository auditing agent.

Usage: python agent.py --repo <github_repository_url> --output report.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from auditor import run_audit
from llm import LLMClient, LLMError
from report import write_report
from tools import clone_repo, normalize_repo_url


def load_dotenv(path: str = ".env") -> None:
    """Tiny .env loader (no dependency); existing environment variables win."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip('"').strip("'")
        if v:
            os.environ.setdefault(k.strip(), v)


def _rmtree(path: str) -> None:
    def onerror(func, p, _exc):  # git packfiles are read-only on Windows
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=onerror, ignore_errors=False)


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Autonomous DevOps auditing agent for public GitHub repos.")
    ap.add_argument("--repo", required=True, help="public GitHub repository URL")
    ap.add_argument("--output", required=True, help="path of the JSON report to write")
    ap.add_argument("--max-steps", type=int, default=int(os.getenv("MAX_STEPS", "30")),
                    help="maximum tool calls the agent may make (default 30)")
    ap.add_argument("--trace", default=None, help="tool-call trace file (default: <output>.trace.json)")
    ap.add_argument("--quiet", action="store_true", help="suppress progress logging")
    return ap.parse_args(argv)


def main(argv=None, llm=None) -> int:
    args = parse_args(argv)
    load_dotenv()
    log = (lambda *_a, **_k: None) if args.quiet else (lambda m: print(m, file=sys.stderr))

    try:
        url = normalize_repo_url(args.repo)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        llm = llm or LLMClient()
    except LLMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix="audit_")
    try:
        log(f"cloning {url} ...")
        try:
            ctx = clone_repo(url, dest=os.path.join(workdir, "repo"))
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
        log(f"auditing with {getattr(llm, 'provider', 'llm')}/{getattr(llm, 'model', '?')} ...")
        try:
            result = run_audit(llm, ctx, max_steps=max(args.max_steps, 5), log=log)
        except (LLMError, RuntimeError) as e:
            print(f"error: audit failed: {e}", file=sys.stderr)
            return 4

        write_report(args.output, url, result.violations)
        trace_path = args.trace or f"{args.output}.trace.json"
        Path(trace_path).write_text(json.dumps(
            {"repository": url, "steps": result.trace, "notes": result.notes}, indent=2), encoding="utf-8")
        log(f"done: {len(result.violations)} violation(s) -> {args.output} (trace: {trace_path})")
        return 0
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    except OSError as e:
        print(f"error: could not write output: {e}", file=sys.stderr)
        return 5
    finally:
        try:
            _rmtree(workdir)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
