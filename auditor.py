"""The agent loop: Observe -> Reason -> Select tool -> Execute -> Interpret -> Report.

The LLM chooses every tool call (including follow-ups) from the previous results.
This module only parses its decision, enforces guardrails, dispatches the tool and
feeds the result back. No agent framework is used.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from prompts import FORCE_FINISH, build_system_prompt
from report import finalize_violations
from tools import RepoContext, TOOLS, execute_tool, redact, truncate

MAX_TOOL_CHARS = 7000
CONTEXT_BUDGET_CHARS = 140_000
MIN_STEPS_BEFORE_FINISH = 6
KEY_FILE = re.compile(
    r"(^|/)(\.github/workflows/[^/]+\.ya?ml|Dockerfile[^/]*|docker-compose[^/]*\.ya?ml|requirements[^/]*\.txt|"
    r"pyproject\.toml|setup\.(py|cfg)|Pipfile(\.lock)?|poetry\.lock|uv\.lock|package(-lock)?\.json|Makefile|"
    r"tox\.ini|\.pre-commit-config\.yaml|\.gitignore|README[^/]*|CODEOWNERS|\.env[^/]*)$", re.I)
PATH_HIT = re.compile(r"^(\S+?):\d+:", re.M)
MAX_BAD_REPLIES = 3


@dataclass
class AuditResult:
    violations: list[dict]
    trace: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def parse_decision(text: str) -> dict:
    """Extract the first JSON object from an LLM reply (tolerates prose/code fences)."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object found")
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                obj = json.loads(text[start:i + 1])
                if not isinstance(obj, dict) or "action" not in obj:
                    raise ValueError("JSON object missing 'action'")
                return obj
    raise ValueError("unterminated JSON object")


def _compact(messages: list[dict]) -> None:
    """Shrink old tool results when the transcript grows past the budget."""
    total = sum(len(m["content"]) for m in messages)
    for m in messages[:-6]:
        if total <= CONTEXT_BUDGET_CHARS:
            break
        if m["role"] == "user" and m["content"].startswith("TOOL RESULT") and len(m["content"]) > 1200:
            new = m["content"][:1200] + "\n... [older output trimmed to save context]"
            total -= len(m["content"]) - len(new)
            m["content"] = new


def run_audit(llm, ctx: RepoContext, max_steps: int = 30, log=print) -> AuditResult:
    system = build_system_prompt(max_steps)
    messages: list[dict] = [{"role": "user", "content": (
        f"Audit this repository: {ctx.url}\n"
        f"It is cloned locally and read-only. It contains {len(ctx.all_files())} files. "
        "Begin your investigation.")}]
    trace: list[dict] = []
    seen_text: list[str] = []
    inspected: set[str] = set()
    seen_calls: set[str] = set()
    bad = 0
    tool_calls = 0
    early_finish_warned = False
    forced = False
    final_raw = None

    while True:
        _compact(messages)
        reply = llm.chat(system, messages)
        messages.append({"role": "assistant", "content": reply})
        try:
            decision = parse_decision(reply)
            bad = 0
        except (ValueError, json.JSONDecodeError) as e:
            bad += 1
            if bad >= MAX_BAD_REPLIES:
                raise RuntimeError(f"LLM returned invalid JSON {bad} times in a row: {e}")
            messages.append({"role": "user", "content":
                             f"Your reply was not a single valid JSON object ({e}). Reply with only the JSON object."})
            continue

        action = str(decision.get("action", "")).strip()
        thought = redact(str(decision.get("thought", "")))[:500]

        if action == "finish":
            listed = any(t["action"] == "list_files" for t in trace)
            unread = [f for f in ctx.all_files() if KEY_FILE.search(f) and f not in inspected]
            if not forced and not early_finish_warned and (
                    tool_calls < MIN_STEPS_BEFORE_FINISH or not listed or unread):
                early_finish_warned = True
                hint = ("; these key files have NOT been opened yet: " + ", ".join(unread[:15])
                        if unread else "")
                messages.append({"role": "user", "content":
                                 "Before finishing, make sure you have investigated enough" + hint +
                                 ". Open any that could hold or rule out a defect (and files you plan to cite), "
                                 "follow up on anything suspicious, then finish. Findings about files you never "
                                 "opened will be discarded."})
                continue
            final_raw = decision.get("violations", [])
            trace.append({"step": len(trace) + 1, "thought": thought, "action": "finish",
                          "args": {}, "result_preview": f"{len(final_raw) if isinstance(final_raw, list) else 0} proposed violations"})
            log(f"[step {len(trace)}] finish: {thought[:120]}")
            break

        if forced:
            raise RuntimeError("LLM kept calling tools after being told to finish")

        args = decision.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        key = action + json.dumps(args, sort_keys=True, default=str)
        if action not in TOOLS:
            result = f"ERROR: unknown tool '{action}'. Available: {', '.join(TOOLS)}, finish"
        elif key in seen_calls:
            result = "NOTE: you already made this exact call; use the earlier result or try something different."
        else:
            seen_calls.add(key)
            result = redact(execute_tool(ctx, action, args))
            seen_text.append(result)
            if action in ("read_file", "inspect_workflow") and not result.startswith("ERROR"):
                inspected.add(str(args.get("path", "")).replace("\\", "/").removeprefix("./"))
            elif action in ("search_code", "scan_secrets"):
                inspected.update(PATH_HIT.findall(result))
        result = truncate(result, MAX_TOOL_CHARS)
        tool_calls += 1
        trace.append({"step": len(trace) + 1, "thought": thought, "action": action, "args": args,
                      "result_preview": result[:300], "ts": time.strftime("%H:%M:%S")})
        log(f"[step {len(trace)}] {action}({json.dumps(args)[:100]}) - {thought[:90]}")

        messages.append({"role": "user", "content":
                         f"TOOL RESULT ({action}):\n{result}\n\n"
                         f"({max_steps - tool_calls} tool calls remaining.) Interpret this result and choose your next action."})
        if tool_calls >= max_steps:
            forced = True
            messages.append({"role": "user", "content": FORCE_FINISH})

    violations, notes = finalize_violations(final_raw, ctx, "\n".join(seen_text))
    return AuditResult(violations=violations, trace=trace, notes=notes)
