"""Validation and normalisation of LLM-proposed violations into the output contract."""
from __future__ import annotations

import json
import re
from pathlib import Path

from tools import RepoContext, redact

SEVERITIES = {"critical", "high", "medium", "low"}
PREFIX = {
    "repository_hygiene": "REPO", "dependency_management": "DEP", "code_quality": "QUAL",
    "testing": "TEST", "ci_cd": "CI", "security": "SEC", "configuration": "CFG",
    "collaboration": "COLLAB", "build_release": "BUILD",
}
CATEGORY_ALIASES = {
    "hygiene": "repository_hygiene", "repository": "repository_hygiene", "repo": "repository_hygiene",
    "dependency": "dependency_management", "dependencies": "dependency_management",
    "quality": "code_quality", "lint": "code_quality", "linting": "code_quality",
    "test": "testing", "tests": "testing",
    "ci": "ci_cd", "cicd": "ci_cd", "ci/cd": "ci_cd", "github_actions": "ci_cd", "actions": "ci_cd",
    "workflow": "ci_cd", "github actions / ci": "ci_cd",
    "config": "configuration", "environment": "configuration",
    "build": "build_release", "release": "build_release", "deployment": "build_release",
    "build_and_release": "build_release", "docker": "build_release",
}
SEVERITY_ALIASES = {"warning": "medium", "moderate": "medium", "major": "high", "minor": "low",
                    "info": "low", "informational": "low", "severe": "critical", "blocker": "critical"}


def normalize_category(raw) -> str | None:
    c = re.sub(r"[\s-]+", "_", str(raw or "").strip().lower())
    if c in PREFIX:
        return c
    return CATEGORY_ALIASES.get(c) or CATEGORY_ALIASES.get(str(raw or "").strip().lower())


def _words(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", s.lower()))


def _similar(a: str, b: str) -> bool:
    wa, wb = _words(a), _words(b)
    return bool(wa and wb) and len(wa & wb) / len(wa | wb) >= 0.6


def _count_lines(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        return 0


def finalize_violations(raw: list, ctx: RepoContext, seen_text: str = "") -> tuple[list[dict], list[str]]:
    """Return (clean violations, notes about dropped/adjusted items).

    ``seen_text`` is everything the tools returned during the investigation; a cited
    file that never appeared there is an unsupported claim and is dropped.
    """
    clean: list[dict] = []
    notes: list[str] = []
    files = set(ctx.all_files())
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            notes.append("dropped non-object violation")
            continue
        cat = normalize_category(item.get("category"))
        desc = redact(str(item.get("description") or "").strip())
        evidence = redact(str(item.get("evidence") or "").strip())
        rec = redact(str(item.get("recommendation") or "").strip())
        if not cat or not desc or not evidence or not rec:
            notes.append(f"dropped incomplete violation: {desc[:60] or '<no description>'}")
            continue
        sev = str(item.get("severity") or "").strip().lower()
        sev = SEVERITY_ALIASES.get(sev, sev)
        if sev not in SEVERITIES:
            sev = "medium"

        file = item.get("file")
        file = str(file).strip().replace("\\", "/").removeprefix("./") if file not in (None, "", "null") else None
        line = item.get("line")
        line = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None
        if file is not None:
            if file not in files:
                # Likely an absence claim ("missing X"): the file legitimately does not exist.
                notes.append(f"file '{file}' not in repository; set to null for: {desc[:50]}")
                file, line = None, None
            elif file not in seen_text:
                notes.append(f"dropped (cited file never inspected): {file}: {desc[:50]}")
                continue
            elif line is not None and line > _count_lines(ctx.root / file):
                line = None
        else:
            line = None

        v = {"rule_id": "", "category": cat, "severity": sev, "file": file, "line": line,
             "description": desc, "evidence": evidence, "recommendation": rec}
        dup = False
        for o in clean:
            same_loc = o["file"] == v["file"] and o["line"] == v["line"]
            if (same_loc and o["category"] == cat and (o["line"] is not None or _similar(o["description"], desc))) \
                    or (o["file"] == v["file"] and _similar(o["description"], desc)):
                dup = True
                break
        if dup:
            notes.append(f"dropped duplicate: {desc[:60]}")
            continue
        clean.append(v)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    clean.sort(key=lambda v: order[v["severity"]])
    counters: dict[str, int] = {}
    for v in clean:
        p = PREFIX[v["category"]]
        counters[p] = counters.get(p, 0) + 1
        v["rule_id"] = f"{p}-{counters[p]:03d}"
    return clean, notes


def write_report(path: str, repository: str, violations: list[dict]) -> None:
    doc = {"repository": repository, "violations": violations}
    text = json.dumps(doc, indent=2, ensure_ascii=False)
    json.loads(text)  # sanity: must round-trip
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text + "\n", encoding="utf-8")
