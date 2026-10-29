"""Optional LangSmith tracing: off means zero langsmith calls; on (stubbed tracer) gives the right tree."""
import json, os, sys, types
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from redcell.attacks.goals import GOALS
from redcell.core import tracing
from redcell.core.session import LiveBrain, run_session
from redcell.intel import tavily_intel
from redcell.target.devops_agent import DevOpsAgent
from test_live_stub import _llm   # local OpenAI-compatible stub server (no network, no spend)

SECRET = "sk-test-SECRET-VALUE-123456"


class _Recorder(types.ModuleType):
    """Fake `langsmith` module: records any attribute access, so we can assert it was never touched."""
    def __init__(self):
        super().__init__("langsmith")
        object.__setattr__(self, "touched", [])
    def __getattr__(self, name):
        self.touched.append(name)
        raise AttributeError(name)


@pytest.mark.parametrize("env", [{"LANGSMITH_TRACING": "false", "LANGSMITH_API_KEY": SECRET},
                                 {"LANGSMITH_TRACING": "true", "LANGSMITH_API_KEY": ""}])
def test_tracing_off_makes_no_langsmith_calls(monkeypatch, env):
    fake = _Recorder()
    monkeypatch.setitem(sys.modules, "langsmith", fake)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(tracing, "_factory", None)
    assert tracing.enabled() is False
    srv, llm = _llm()
    res = run_session(DevOpsAgent(llm=llm, model="target"), LiveBrain(llm, "planner", "judge"), ["tool_misuse"])
    srv.shutdown()
    assert res[0].landed                      # the run behaves exactly as without tracing
    assert fake.touched == []                 # and langsmith was never called


class _Node:
    def __init__(self, name, run_type, inputs, metadata):
        self.name, self.run_type, self.inputs, self.metadata = name, run_type, inputs, dict(metadata)
        self.children, self.outputs = [], None
    def add_metadata(self, m): self.metadata.update(m)
    def end(self, outputs=None): self.outputs = outputs
    def get_url(self): return "stub://" + self.name
    def dump(self): return {"name": self.name, "type": self.run_type, "inputs": self.inputs, "metadata": self.metadata,
                            "outputs": self.outputs, "children": [c.dump() for c in self.children]}


class _StubTracer:
    """Same call shape as langsmith.trace: nests by an explicit stack."""
    def __init__(self):
        self.stack, self.roots = [], []
    def __call__(self, name, run_type, inputs=None, metadata=None):
        tracer = self
        class _CM:
            def __enter__(self_):
                node = _Node(name, run_type, inputs or {}, metadata or {})
                (tracer.stack[-1].children if tracer.stack else tracer.roots).append(node)
                tracer.stack.append(node)
                return node
            def __exit__(self_, *exc):
                tracer.stack.pop()
        return _CM()


def test_stubbed_tracer_gets_the_right_tree(monkeypatch):
    stub = _StubTracer()
    monkeypatch.setattr(tracing, "_factory", stub)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    srv, llm = _llm()
    llm.api_key = SECRET                       # must never reach a trace
    with tracing.span("RedCell run", "chain", inputs={"target": "OrbitOps", "hardened": False, "brain": "nemotron-live"}) as run_span:
        tavily_intel.gather([GOALS["tool_misuse"]], api_key="", cache_path=os.devnull + ".none")
        run_session(DevOpsAgent(llm=llm, model="target"), LiveBrain(llm, "planner", "judge"), ["tool_misuse"])
        run_span.end(outputs={"goals_broken": 1})
    srv.shutdown()

    assert len(stub.roots) == 1
    root = stub.roots[0]
    assert root.name == "RedCell run" and root.inputs["brain"] == "nemotron-live"
    assert [c.name for c in root.children] == ["tavily intel", "goal: tool_misuse", "replay: tool_misuse"]
    assert root.children[0].run_type == "tool"

    goal = root.children[1]
    names = [c.name for c in goal.children]
    assert names[0] == "planner: planner" and "target: target" in names and names[-1] == "judge: turn 1"
    llm_calls = [c for c in goal.children if c.run_type == "llm"]
    for c in llm_calls:                        # model, tokens, cost, latency, finish_reason on every LLM call
        assert c.metadata["ls_model_name"] in ("planner", "target")
        assert {"cost_usd", "latency_ms", "finish_reason"} <= set(c.metadata) and c.metadata["cost_usd"] > 0
        assert c.outputs["usage_metadata"] == {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}
    judge = goal.children[-1]                  # landed by code check: filterable metadata, no judge-model call needed
    assert judge.metadata["turn"] == 1 and judge.metadata["verdict"] == "landed"
    assert "rm -rf /srv/data" in judge.metadata["evidence"] and judge.metadata["decided_by"] == "code check"
    assert root.children[2].metadata["reproduced"] is True

    blob = json.dumps(root.dump())
    assert SECRET not in blob and "Authorization" not in blob and "Bearer" not in blob


def test_tracer_errors_never_affect_a_run(monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("tracing backend down")
    monkeypatch.setattr(tracing, "_factory", broken)
    srv, llm = _llm()
    res = run_session(DevOpsAgent(llm=llm, model="target"), LiveBrain(llm, "planner", "judge"), ["tool_misuse"])
    srv.shutdown()
    assert res[0].landed
