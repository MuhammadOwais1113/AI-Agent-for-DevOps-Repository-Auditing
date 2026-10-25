import json

import pytest

import agent
from auditor import parse_decision, run_audit
from report import finalize_violations


class ScriptedLLM:
    """Fake LLM replaying scripted replies; records what it was shown."""
    provider, model = "fake", "fake"

    def __init__(self, replies):
        self.replies = list(replies)
        self.seen = []

    def chat(self, system, messages, max_tokens=4096):
        self.seen.append(messages[-1]["content"])
        return self.replies.pop(0)


def j(**kw):
    return json.dumps(kw)


FINDING = {"category": "ci", "severity": "HIGH", "file": ".github/workflows/ci.yml", "line": 9,
           "quote": "run: pytest || true",
           "description": "Test failures swallowed", "evidence": "pytest || true in workflow",
           "recommendation": "Remove the '|| true' so failures fail the job"}
QUIET = lambda *_: None  # noqa: E731


def test_parse_decision_tolerates_fences_and_prose():
    d = parse_decision('Sure!\n```json\n{"action": "list_files", "args": {}}\n```')
    assert d["action"] == "list_files"


def test_loop_follows_up_based_on_observation(repo):
    llm = ScriptedLLM([
        j(thought="start", action="list_files", args={}),
        j(thought="CI file seen, inspect", action="inspect_workflow", args={"path": ".github/workflows/ci.yml"}),
        j(thought="confirm", action="read_file", args={"path": ".github/workflows/ci.yml"}),
        j(thought="look for secrets", action="search_code", args={"pattern": "API_KEY"}),
        j(thought="done", action="finish", violations=[FINDING]),  # nudged: not enough steps yet
        j(thought="confirmed", action="finish", violations=[FINDING]),
    ])
    res = run_audit(llm, repo, max_steps=10, log=QUIET)
    assert [t["action"] for t in res.trace] == ["list_files", "inspect_workflow", "read_file", "search_code", "finish"]
    # the previous tool output is fed back to the LLM before its next decision
    assert any("TOOL RESULT (inspect_workflow)" in s for s in llm.seen)
    v = res.violations[0]
    assert v["rule_id"] == "CI-001" and v["category"] == "ci_cd" and v["severity"] == "high"


def test_early_finish_is_pushed_back(repo):
    llm = ScriptedLLM([j(action="finish", violations=[]), j(action="list_files", args={}),
                       j(action="git_log", args={}), j(action="git_status", args={}),
                       j(action="read_file", args={"path": "README.md"}), j(action="finish", violations=[])])
    res = run_audit(llm, repo, max_steps=10, log=QUIET)
    assert res.violations == [] and [t["action"] for t in res.trace][0] == "list_files"


def test_invalid_json_recovers_then_fails(repo):
    llm = ScriptedLLM(["nonsense", j(action="list_files", args={})] + ["bad"] * 3)
    with pytest.raises(RuntimeError, match="invalid JSON"):
        run_audit(llm, repo, max_steps=10, log=QUIET)


def test_step_limit_forces_finish(repo):
    llm = ScriptedLLM([j(action="list_files", args={"directory": "src"}),
                       j(action="git_log", args={}),
                       j(action="finish", violations=[])])
    res = run_audit(llm, repo, max_steps=2, log=QUIET)
    assert res.trace[-1]["action"] == "finish"


def test_finalize_drops_unsupported_and_dedups(repo):
    seen = "workflow output .github/workflows/ci.yml 9: - run: pytest || true"
    raw = [
        FINDING,
        dict(FINDING, description="Test failures swallowed again", line=None),   # duplicate
        dict(FINDING, file="src/app.py", description="X", line=999),            # never inspected -> dropped
        dict(FINDING, file="ghost.py", description="Missing thing"),            # nonexistent -> file null
        {"category": "security", "description": "no evidence"},                   # incomplete
        dict(FINDING, severity="weird", line=None, description="Other issue entirely different"),
    ]
    out, notes = finalize_violations(raw, repo, seen)
    assert notes
    assert {v["severity"] for v in out} <= {"critical", "high", "medium", "low"}
    assert any(v["file"] is None for v in out)
    assert not any(v["file"] == "src/app.py" for v in out)
    assert all(set(v) == {"rule_id", "category", "severity", "file", "line", "description",
                          "evidence", "recommendation"} for v in out)
    assert len({v["rule_id"] for v in out}) == len(out)


def test_secrets_scrubbed_from_report(repo):
    f = dict(FINDING, evidence="key sk-abcdefghijklmnopqrstuvwxyz123456 in code")
    out, _ = finalize_violations([f], repo, ".github/workflows/ci.yml 9: - run: pytest || true")
    assert "sk-abcdef" not in out[0]["evidence"]


def test_cli_end_to_end_writes_valid_json(repo, tmp_path, monkeypatch):
    llm = ScriptedLLM([j(action="list_files", args={}), j(action="git_log", args={}),
                       j(action="read_file", args={"path": "README.md"}),
                       j(action="git_status", args={}), j(action="finish", violations=[]),
                       j(action="finish", violations=[])])
    monkeypatch.setattr(agent, "clone_repo", lambda url, dest=None, depth=200: repo)
    out = tmp_path / "report.json"
    rc = agent.main(["--repo", "https://github.com/example/demo", "--output", str(out), "--quiet"], llm=llm)
    assert rc == 0
    assert json.loads(out.read_text()) == {"repository": "https://github.com/example/demo", "violations": []}


def test_cli_rejects_bad_url_and_missing_key(tmp_path, monkeypatch, capsys):
    out = str(tmp_path / "r.json")
    assert agent.main(["--repo", "not-a-url", "--output", out], llm=object()) == 2
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here
    assert agent.main(["--repo", "https://github.com/a/b", "--output", out]) == 2
    assert "error" in capsys.readouterr().err


def test_finding_dropped_without_verbatim_quote_or_unopened_file(repo):
    seen = "9: - run: pytest || true"
    inspected = {".github/workflows/ci.yml"}
    ok = FINDING
    no_quote = dict(FINDING, description="Another", quote=None)
    fake_quote = dict(FINDING, description="Third thing", quote="FROM python:latest")
    unopened = dict(FINDING, file="src/app.py", description="Fourth", quote="API_KEY")
    out, notes = finalize_violations([ok, no_quote, fake_quote, unopened], repo, seen, inspected)
    assert len(out) == 1
    assert sum("dropped" in n for n in notes) == 3


def test_nudge_lists_unopened_key_files(repo):
    llm = ScriptedLLM([j(action="list_files", args={}), j(action="git_log", args={}),
                       j(action="git_status", args={}), j(action="search_code", args={"pattern": "x"}),
                       j(action="git_log", args={"max_count": 5}), j(action="git_log", args={"max_count": 6}),
                       j(action="finish", violations=[]), j(action="finish", violations=[])])
    run_audit(llm, repo, max_steps=10, log=QUIET)
    nudge = next(s for s in llm.seen if "have NOT been opened" in s)
    assert ".github/workflows/ci.yml" in nudge and "README.md" in nudge
