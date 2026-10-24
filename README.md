# DevOps Repository Auditing Agent

An autonomous agent that audits a public GitHub repository for DevOps best-practice violations and writes an
evidence-based JSON report. The LLM drives the investigation: it picks each inspection tool, reads the result,
and decides the next call. There is no fixed checklist and no agent framework (no LangChain/LangGraph/n8n);
the loop, tool dispatch and guardrails are plain Python.

## Install

Requires Python 3.10+ and `git` on PATH.

```bash
git clone <this-repo-url> && cd <this-repo>
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt                       # pytest + optional ruff; runtime is stdlib only
cp .env.example .env                                  # then edit .env
```

Set in `.env` (or the environment):

| Variable | Meaning |
|---|---|
| `LLM_PROVIDER` | `anthropic` or `openai` (`openai` = any OpenAI-compatible API: OpenAI, Groq, OpenRouter, Gemini's OpenAI endpoint, Ollama) |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | key for the chosen provider |
| `LLM_MODEL` | optional model override (defaults: `claude-sonnet-5-5`, `gpt-4o-mini`) |
| `OPENAI_BASE_URL` | optional, for OpenAI-compatible providers |
| `MAX_STEPS` | optional tool-call budget (default 30) |

## Run

```bash
python agent.py --repo https://github.com/example/demo-project --output report.json
```

Unattended, no prompts. Progress goes to stderr; `report.json` is the contract output
(`{"repository": ..., "violations": [...]}`, each violation with `rule_id, category, severity, file, line,
description, evidence, recommendation`). A tool-call trace is written to `report.json.trace.json`
(every step's reasoning, tool, arguments and result preview) for verification.

Exit codes: `0` success, `2` bad URL / missing API key, `3` clone failed, `4` audit failed (LLM error),
`5` cannot write output. On fatal errors no report is written and a message is printed to stderr.

## Architecture

```
agent.py     CLI: validate URL -> shallow clone to temp dir -> run audit -> write report/trace -> clean up
auditor.py   Agent loop: LLM decision (JSON) -> guardrails -> tool dispatch -> result fed back -> repeat -> finish
prompts.py   System prompt: protocol, DevOps knowledge areas, evidence rules (acceptable alternatives, no speculation)
llm.py       Stdlib HTTP client for Anthropic / OpenAI-compatible APIs with retry + backoff
tools.py     Read-only inspection tools + secret redaction + safe cloning
report.py    Validates/normalises LLM findings into the output contract (dedup, grounding, redaction)
```

Cycle: **Observe** (tool output) -> **Reason** (LLM `thought`) -> **Select tool** (LLM `action`+`args`) ->
**Execute** (`execute_tool`) -> **Interpret** (result appended to the conversation) -> **Report** (`finish`).

Tools: `list_files`, `read_file`, `search_code`, `git_log` (required) plus `git_status` (tracked
generated/temp files, `.gitignore`), `run_ruff` (static lint, skipped if ruff is missing), `inspect_workflow`
(GitHub Actions triggers/permissions/risky constructs) and `scan_secrets` (locations only, values never shown).
Scanner-style tools only produce *candidates*; the prompt requires the LLM to confirm in context before reporting.

### Precision safeguards
- Prompt rules: absent optional files are not defects if an equivalent exists; remote branch protection is never
  inferred; placeholders are not secrets; a healthy repo may return `[]`.
- `report.py` drops findings that lack evidence/recommendation, cite a file the agent never inspected,
  or duplicate another finding; invalid file/line values become `null`; severities/categories are normalised.
- Minimum-investigation guard: the agent cannot finish before listing files and making several tool calls.

### Safety
- Target is cloned shallow (`--depth 200`) with hooks disabled and symlinks off; it is **never executed**
  (no pytest/pip/make on the target; ruff runs with `--isolated` as pure static analysis).
- All tools are read-only; paths cannot escape the clone; the clone lives in a temp dir that is deleted afterwards.
- Secrets are redacted (known token formats and `key = "literal"` assignments) before reaching the LLM, logs,
  trace or report. Tool output is treated as untrusted data; the prompt tells the LLM not to follow instructions in it.
- Handles invalid URLs, clone failures, tool errors, LLM HTTP errors/timeouts (retries), malformed LLM JSON
  (re-prompt, then fail), and a step budget (forced finish).

## Tests

```bash
python -m pytest -q
```
Tests build a local git repo with seeded defects and use a scripted fake LLM (no network/API key needed) to
verify tools, redaction, path-traversal protection, the dynamic loop, guardrails, report validation and the CLI.

## Sample report

`sample_report.json` is real output of the agent against a public repository; regenerate with the run command above.

## Limitations
Findings depend on the chosen LLM; large repositories are sampled within the step budget; only GitHub public
URLs are supported; remote settings (branch protection, secrets) are deliberately not assessed.
