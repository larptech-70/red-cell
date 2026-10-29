"""Tests for concrete code-remediation generation (patches + hardened source)."""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.attacks.goals import GOALS
from redcell.core.llm import Ledger
from redcell.core.session import MockBrain, run_session
from redcell.reporting import remediation
from redcell.reporting import report
from redcell.target.devops_agent import DevOpsAgent


def _load_hardened_target():
    """Import the generated hardened devops_agent as a package module."""
    src = remediation.hardened_source()
    mod = types.ModuleType("redcell.target.hardened_devops_agent")
    mod.__package__ = "redcell.target"
    mod.__file__ = "redcell/target/hardened_devops_agent.py"
    sys.modules[mod.__name__] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    return mod


def test_hardened_source_is_valid_python():
    compile(remediation.hardened_source(), "hardened_devops_agent.py", "exec")


def test_patch_applies_cleanly():
    assert remediation.patch_applies() is True


def test_generated_hardened_target_holds_every_goal():
    mod = _load_hardened_target()
    res = run_session(mod.DevOpsAgent(mock=True), MockBrain(), list(GOALS))
    # The patch must neutralise even the gullible weak bot.
    assert not any(r.landed for r in res)


def test_unpatched_weak_target_still_breaks_every_goal():
    res = run_session(DevOpsAgent(mock=True), MockBrain(), list(GOALS))
    assert all(r.landed for r in res)


def test_build_writes_applyable_artifacts(tmp_path):
    res = run_session(DevOpsAgent(mock=True), MockBrain(), ["tool_misuse", "secret_leak"])
    man = remediation.build(res, str(tmp_path))
    assert man["applies"] is True
    assert os.path.exists(os.path.join(str(tmp_path), "redcell-hardening.patch"))
    assert os.path.exists(os.path.join(str(tmp_path), "hardened_devops_agent.py"))
    assert set(man["by_goal"]) == {"tool_misuse", "secret_leak"}
    assert "allowlist" in man["by_goal"]["tool_misuse"]["defence"].lower()


def test_report_attaches_remediation(tmp_path):
    res = run_session(DevOpsAgent(mock=True), MockBrain(), ["tool_misuse"])
    rep = report.build(res, Ledger().snapshot(), target_name="t", hardened=False, mode="mock",
                       patches_dir=str(tmp_path))
    assert rep["patches"]["applies"] is True
    f = rep["findings"][0]
    assert f["remediation"]["defence"]
    md = report.to_markdown(rep)
    assert "Remediation patch" in md and "redcell-hardening.patch" in md
    assert "Remediation:" in md


def test_patch_is_computed_from_current_source():
    # The transform anchors on the live devops_agent.py, so it stays correct as the
    # target evolves; a stale anchor must raise rather than emit a broken patch.
    src = remediation.weak_source()
    assert "if self.hardened and classify(cmd)[0] != \"safe\"" in src
    assert "from .simshell import CANARY_PROMPT_MARK, SimShell" in src
