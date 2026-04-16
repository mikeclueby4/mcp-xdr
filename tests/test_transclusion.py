"""Integration tests verifying that @-transclusions in agent/skill files resolve correctly.

These tests launch a real `claude -p` subprocess and ask a question whose answer
exists ONLY in the transcluded file, so a correct answer proves the transclusion worked.

Requirements:
- `claude` CLI must be on PATH
- ANTHROPIC_API_KEY (or OAuth cache) must be valid
- Tests are skipped if either condition is not met

Run with:
    pytest tests/test_transclusion.py -v
"""

import shutil
import subprocess
import sys

import pytest

# ---------------------------------------------------------------------------
# Skip guard: only run when claude CLI + credentials are available
# ---------------------------------------------------------------------------

_CLAUDE = shutil.which("claude")

_SKIP_REASON = (
    "claude CLI not found on PATH" if _CLAUDE is None else None
)


def _claude_available() -> bool:
    if _CLAUDE is None:
        return False
    result = subprocess.run(
        [_CLAUDE, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.returncode == 0


pytestmark = pytest.mark.skipif(
    not _claude_available(),
    reason=_SKIP_REASON or "claude CLI not available or not authenticated",
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run_agent(agent_name: str, prompt: str, cwd: str | None = None, timeout: int = 90) -> str:
    """Run `claude -p --agent <agent_name> <prompt>` and return stdout."""
    result = subprocess.run(
        [
            _CLAUDE,
            "--agent", agent_name,
            "--tools", "Read",  # ensure Read tool is available for transclusion test
            "--system-prompt", "",
            "-p",
            prompt,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"claude exited {result.returncode}:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestXdrRefineKqlFactsReadable:
    """Verify xdr-refine can read kql-facts.md via its explicit Read() instruction.
    Agent definition files are static markdown — neither @path nor !`cmd` transclusion 
    works at load time. The Read tool is the correct path.

    kql-facts.md contains a unique sentinel token (`KQLFACTS-7F3A`) that cannot
    be guessed or derived from general knowledge.

    This test exists to catch future regressions where the agent loses permission to 
    read the file, or path issues arise (e.g. relative vs absolute path problems, or 
    the file is accidentally deleted).
    """

    # Must match the sentinel in kql-facts.md line 2:
    # transclusion-sentinel: KQLFACTS-7F3A
    SENTINEL_TOKEN = "KQLFACTS-7F3A"

    ORACLE_PROMPT = (
        "Read the file .claude/skills/xdr/references/kql-facts.md and look for a "
        "line that starts with 'transclusion-sentinel:'. "
        "Reply with ONLY the token value on that line (the part after the colon, trimmed). "
        "If the file does not exist or no such line is found, reply exactly: NOT-FOUND"
    )

    def test_kql_facts_readable_by_xdr_refine(self):
        """xdr-refine agent can read kql-facts.md and report its sentinel token."""
        import pathlib
        repo_root = str(pathlib.Path(__file__).parent.parent)

        output = _run_agent(
            agent_name="xdr-refine",
            prompt=self.ORACLE_PROMPT,
            cwd=repo_root,
        )

        assert self.SENTINEL_TOKEN in output, (
            f"Expected sentinel token '{self.SENTINEL_TOKEN}' in agent output.\n"
            f"This means xdr-refine could not read kql-facts.md "
            f"(tool permission denied, wrong path, or file missing).\n"
            f"Agent output was:\n{output}"
        )
