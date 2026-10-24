import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import RepoContext  # noqa: E402


@pytest.fixture
def repo(tmp_path):
    """A small local git repo with deliberate defects (never touches the network)."""
    r = tmp_path / "r"
    (r / ".github" / "workflows").mkdir(parents=True)
    (r / "src").mkdir()
    (r / "README.md").write_text("# demo\n")
    (r / "src" / "app.py").write_text(
        'import os\nAPI_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\nPATH = "C:\\\\Users\\\\bob\\\\data"\n'
        'ok = os.getenv("TOKEN")\n')
    (r / "__pycache__").mkdir()
    (r / "__pycache__" / "app.cpython-311.pyc").write_bytes(b"\x00\x01")
    (r / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non:\n  pull_request_target:\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@main\n      - run: pytest || true\n")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    for cmd in (["init", "-q"], ["add", "-f", "."], ["commit", "-q", "-m", "initial commit"]):
        subprocess.run(["git", "-C", str(r), *cmd], check=True, env=env, capture_output=True)
    return RepoContext(root=r, url="https://github.com/example/demo")
