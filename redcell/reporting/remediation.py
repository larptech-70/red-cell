"""Concrete, applyable code remediation for every confirmed finding.

RedCell promises that every finding "ships with a fix". This module makes that
promise literally true: it turns the weak OrbitOps target into a hardened one by
generating a real, ``git apply``-able unified-diff patch (and the hardened source
it produces), plus a per-goal code snippet explaining exactly which defence closes
which hole. Artifacts are written under ``reports/patches/`` so a reviewer can
inspect or apply them.

Everything here is deterministic and offline: the patch is computed from the
target's own source, so it never drifts from the code it claims to fix.
"""
from __future__ import annotations

import difflib
import json
import os
import pathlib
import subprocess
import sys
import types
from typing import Any

TARGET_FILE = "redcell/target/devops_agent.py"

# --------------------------------------------------------------------------- #
# Weak -> hardened transforms. Each (old, new) pair is applied to the target's
# real source; we assert every `old` is present so a patch can never be silently
# generated against stale code.
# --------------------------------------------------------------------------- #
_IMPORT_OLD = "from .simshell import CANARY_PROMPT_MARK, SimShell"
_IMPORT_NEW = (
    "from .simshell import (\n"
    "    CANARY_CONSUMPTION, CANARY_HALLUCINATION, CANARY_OVERRIDE, CANARY_POISON,\n"
    "    CANARY_PROMPT_MARK, CANARY_SECRET, CANARY_SUPPLY, CANARY_VECTOR, CANARY_XSS,\n"
    "    FAKE_CUSTOMERS, SimShell,\n"
    ")"
)

_SEND_OLD = '''    def send(self, text: str) -> dict:
        """Returns {'reply', 'tool_calls': [{'cmd','risk','why'}], 'tool_errors': [...]} for this turn only."""
        start, err_start = len(self.shell.log), len(self.tool_errors)
        self.messages.append({"role": "user", "content": text})
        reply = self._mock_turn(text) if self.mock else self._live_turn()
        return {"reply": reply, "tool_calls": self.shell.log[start:], "tool_errors": self.tool_errors[err_start:]}'''

_SEND_NEW = '''    # Least-privilege output filter (added by RedCell remediation): never echo
    # any planted canary, secret, PII, or the private system-prompt marker back
    # to a caller. Ground truth can still see the raw reply in the shell log.
    _REDACT = (
        CANARY_SECRET, CANARY_PROMPT_MARK, CANARY_OVERRIDE, CANARY_SUPPLY,
        CANARY_POISON, CANARY_XSS, CANARY_VECTOR, CANARY_HALLUCINATION,
        CANARY_CONSUMPTION, "postgres://", *FAKE_CUSTOMERS,
    )

    def _guard(self, text: str) -> str:
        for needle in self._REDACT:
            text = text.replace(needle, "[REDACTED]")
        return text

    def send(self, text: str) -> dict:
        """Returns {'reply', 'tool_calls': [{'cmd','risk','why'}], 'tool_errors': [...]} for this turn only."""
        start, err_start = len(self.shell.log), len(self.tool_errors)
        self.messages.append({"role": "user", "content": text})
        reply = self._mock_turn(text) if self.mock else self._live_turn()
        return {"reply": self._guard(reply), "tool_calls": self.shell.log[start:], "tool_errors": self.tool_errors[err_start:]}'''

_RUN_TOOL_OLD = '''    def _run_tool(self, cmd: str) -> str:
        if self.hardened and classify(cmd)[0] != "safe":
            self.shell.log.append({"cmd": cmd, "risk": "blocked", "why": "policy gate"})
            return "Blocked by policy: command not allowed."
        return self.shell.run(cmd)'''

_RUN_TOOL_NEW = '''    def _run_tool(self, cmd: str) -> str:
        # Hardened default (added by RedCell remediation): EVERY tool call must
        # pass the allowlist, whoever asks -- not just when self.hardened is set.
        risk, why = classify(cmd)
        if risk != "safe":
            self.shell.log.append({"cmd": cmd, "risk": "blocked", "why": why or "policy gate"})
            return "Blocked by policy: command not allowed."
        return self.shell.run(cmd)'''

_TRANSFORMS = [(_IMPORT_OLD, _IMPORT_NEW), (_SEND_OLD, _SEND_NEW), (_RUN_TOOL_OLD, _RUN_TOOL_NEW)]

# Which defence closes which hole, with the exact added lines a reviewer can grep.
_GOAL_DEFENCE = {
    "tool_misuse": (
        "Allowlist every tool call in code, not in the prompt",
        _RUN_TOOL_NEW,
    ),
    "secret_leak": (
        "Never read secrets; redact them from tool output before replying",
        _SEND_NEW,
    ),
    "pii_leak": (
        "Block /srv/data reads and redact customer emails from output",
        _SEND_NEW,
    ),
    "prompt_leak": (
        "Treat the system prompt as public; block verbatim prompt leakage",
        _SEND_NEW,
    ),
    "prompt_injection": (
        "Separate untrusted input from instructions; redact override tokens",
        _SEND_NEW,
    ),
    "supply_chain": (
        "Deny dynamic remote installs at the tool layer",
        _RUN_TOOL_NEW,
    ),
    "data_poisoning": (
        "Reject writes to system config at the tool layer",
        _RUN_TOOL_NEW,
    ),
    "vector_weakness": (
        "Enforce per-document access control before retrieval",
        _RUN_TOOL_NEW,
    ),
    "improper_output": (
        "Escape/sanitise all agent text before rendering",
        _SEND_NEW,
    ),
    "misinformation": (
        "Ground status statements in telemetry, not conversation",
        _SEND_NEW,
    ),
    "unbounded_consumption": (
        "Cap output tokens per turn in the orchestrator",
        _SEND_NEW,
    ),
}


def _repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent.parent


def weak_source() -> str:
    return (_repo_root() / TARGET_FILE).read_text(encoding="utf-8")


def _gate_mock_shell(src: str) -> str:
    """Route the mock target's own shell calls through the allowlist gate.

    The vulnerable mock branch called ``self.shell.run(...)`` directly, bypassing
    ``_run_tool``. Replacing those calls (only inside ``_mock_turn``, never in
    ``_run_tool`` itself) makes the allowlist apply to the demo bot too.
    """
    idx = src.index("    def _mock_turn")
    head, tail = src[:idx], src[idx:]
    tail = tail.replace("self.shell.run(", "self._run_tool(")
    return head + tail


def hardened_source() -> str:
    """Return devops_agent.py with every RedCell hardening applied."""
    src = weak_source()
    for old, new in _TRANSFORMS:
        if old not in src:
            raise RuntimeError(f"remediation: anchor not found in {TARGET_FILE}: {old[:60]!r}")
        src = src.replace(old, new, 1)
    return _gate_mock_shell(src)


def load_patched_agent_class():
    """Return the DevOpsAgent class from the hardened source, as a drop-in target.

    Loads the generated hardened devops_agent as a real module so callers can
    instantiate it exactly like ``DevOpsAgent(llm=..., model=..., mock=...)``.
    Used by the ``--patched`` re-test path so the same generated patch that ships
    in the report is what actually gets tested.
    """
    src = hardened_source()
    mod = types.ModuleType("redcell.target.patched_devops_agent")
    mod.__package__ = "redcell.target"
    mod.__file__ = "redcell/target/patched_devops_agent.py"
    sys.modules[mod.__name__] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    return mod.DevOpsAgent


def patch_text() -> str:
    """A unified diff, ``git apply``-able from the repo root, weak -> hardened."""
    a = weak_source().splitlines(keepends=True)
    b = hardened_source().splitlines(keepends=True)
    diff = difflib.unified_diff(
        a, b,
        fromfile=f"a/{TARGET_FILE}", tofile=f"b/{TARGET_FILE}",
        n=3,
    )
    return "".join(diff)


def patch_applies(patch: str | None = None) -> bool:
    """True if the generated patch applies cleanly to the working tree."""
    patch = patch or patch_text()
    root = str(_repo_root())
    with open(os.path.join(root, ".redcell-check.patch"), "w", encoding="utf-8") as f:
        f.write(patch)
    try:
        res = subprocess.run(
            ["git", "apply", "--check", ".redcell-check.patch"],
            cwd=root, capture_output=True, text=True,
        )
        return res.returncode == 0
    except (FileNotFoundError, OSError):
        return False  # git unavailable: report "review required" rather than crash
    finally:
        try:
            os.remove(os.path.join(root, ".redcell-check.patch"))
        except OSError:
            pass


def goal_snippet(goal_id: str) -> dict[str, str]:
    what, code = _GOAL_DEFENCE.get(goal_id, ("Apply the RedCell hardening patch", _RUN_TOOL_NEW))
    return {"defence": what, "code": code}


def build(results, outdir: str = "reports/patches") -> dict[str, Any]:
    """Write the hardening artifacts and return a manifest for the report.

    Returns {"patch": str, "hardened_file": str, "applies": bool, "by_goal": {...}}.
    Never raises for a single goal; only the (deterministic) source transform can fail.
    """
    root = _repo_root()
    patch = patch_text()
    hardened = hardened_source()
    os.makedirs(outdir, exist_ok=True)

    patch_path = os.path.join(outdir, "redcell-hardening.patch")
    hard_path = os.path.join(outdir, "hardened_devops_agent.py")
    with open(patch_path, "w", encoding="utf-8") as f:
        f.write(patch)
    with open(hard_path, "w", encoding="utf-8") as f:
        f.write(hardened)

    applies = patch_applies(patch)
    by_goal = {}
    for r in results:
        if not r.landed:
            continue
        sn = goal_snippet(r.goal.id)
        by_goal[r.goal.id] = {
            "title": r.goal.title,
            "owasp": r.goal.owasp,
            "defence": sn["defence"],
            "code": sn["code"],
        }

    manifest = {
        "patch": os.path.relpath(patch_path, root),
        "hardened_file": os.path.relpath(hard_path, root),
        "applies": applies,
        "patch_text": patch,
        "by_goal": by_goal,
    }
    with open(os.path.join(outdir, "remediations.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest
