import pytest

from tools import (ToolError, execute_tool, git_log, git_status, inspect_workflow, list_files,
                   normalize_repo_url, read_file, redact, scan_secrets, search_code)


def test_list_files(repo):
    out = list_files(repo)
    assert "README.md" in out and "src/app.py" in out and ".git/" not in out
    assert "src/app.py" in list_files(repo, "src")


def test_read_file_numbers_and_redacts(repo):
    out = read_file(repo, "src/app.py")
    assert "2: API_KEY" in out
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in out
    assert "REDACTED" in out


def test_read_file_blocks_traversal_and_missing(repo):
    with pytest.raises(ToolError):
        read_file(repo, "../outside.txt")
    with pytest.raises(ToolError):
        read_file(repo, "nope.txt")
    assert execute_tool(repo, "read_file", {"path": "nope.txt"}).startswith("ERROR")


def test_search_code(repo):
    assert "src/app.py:3" in search_code(repo, "Users")
    assert "No matches" in search_code(repo, "zzzzqqq")
    assert "ERROR" in execute_tool(repo, "search_code", {"pattern": "("})


def test_git_log(repo):
    assert "initial commit" in git_log(repo)


def test_git_status_flags_tracked_pyc(repo):
    out = git_status(repo)
    assert "__pycache__" in out and ".gitignore: ABSENT" in out


def test_inspect_workflow(repo):
    out = inspect_workflow(repo, ".github/workflows/ci.yml")
    assert "pull_request_target" in out and "write-all" in out
    assert "mutable branch" in out and "swallows failures" in out


def test_scan_secrets_never_prints_value(repo):
    out = scan_secrets(repo)
    assert "src/app.py:2" in out and "sk-abcdefghijklmnopqrstuvwxyz123456" not in out


def test_redact_ignores_placeholders():
    assert redact('password = "changeme123"') == 'password = "changeme123"'
    assert "REDACTED" in redact('db_password = "Zx9!realvalue"')


def test_unknown_tool_and_bad_args(repo):
    assert "unknown tool" in execute_tool(repo, "rm_rf", {})
    assert "bad arguments" in execute_tool(repo, "list_files", {"bogus": 1})


def test_url_validation():
    assert normalize_repo_url("https://github.com/a/b.git/") == "https://github.com/a/b"
    for bad in ["", "ftp://github.com/a/b", "https://gitlab.com/a/b", "https://github.com/a"]:
        with pytest.raises(ValueError):
            normalize_repo_url(bad)
