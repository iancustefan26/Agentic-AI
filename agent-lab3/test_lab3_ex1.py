"""Deterministic tests for the Ex1 harness - no LLM calls. Run: pytest test_lab3_ex1.py -v"""
from types import SimpleNamespace

import agent_core
from agent_core import execute_tool, run_agent


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


def broken() -> str:
    """A tool that always crashes."""
    raise RuntimeError("disk on fire")


TOOLS = {"add": add, "broken": broken}


# --- execute_tool: every failure becomes an ERROR string --------------------
def test_success_is_a_string():
    assert execute_tool(TOOLS, "add", {"a": 2, "b": 3}) == "5"


def test_unknown_tool():
    out = execute_tool(TOOLS, "delete_everything", {})
    assert out.startswith("ERROR: Unknown tool 'delete_everything'")
    assert "add" in out and "broken" in out  # the model learns what exists


def test_bad_arguments():
    assert execute_tool(TOOLS, "add", {"a": 1}).startswith("ERROR: Bad arguments for add")
    assert execute_tool(TOOLS, "add", {"a": 1, "b": 2, "c": 3}).startswith("ERROR: Bad arguments for add")


def test_tool_exception():
    assert execute_tool(TOOLS, "broken", {}) == "ERROR: broken failed: disk on fire"


# --- run_agent with a fake model that always asks for the same call ---------
def fake_model_always(name, args):
    """Returns a fake call_llm that keeps asking for the same tool call (a stuck model)."""
    def fake_call_llm(contents, config):
        call = SimpleNamespace(name=name, args=args, id="call-1")
        return SimpleNamespace(
            usage_metadata=SimpleNamespace(prompt_token_count=100),
            candidates=[SimpleNamespace(content=SimpleNamespace(parts=[]))],
            function_calls=[call],
            text=None,
        )
    return fake_call_llm


def test_stuck_detector_stops_on_third_identical_call(monkeypatch):
    monkeypatch.setattr(agent_core, "call_llm", fake_model_always("add", {"a": 1, "b": 2}))
    result = run_agent("x", tools=[add], system_instruction="x", max_steps=8, verbose=False)
    assert result.stop_reason == "stuck"
    assert result.steps == 3


def test_unknown_tool_does_not_crash_the_loop(monkeypatch):
    # an unknown tool 8 times with different args: never stuck, ends on the step budget
    calls = iter(range(100))

    def fake_call_llm(contents, config):
        call = SimpleNamespace(name="nope", args={"i": next(calls)}, id="c")
        return SimpleNamespace(
            usage_metadata=SimpleNamespace(prompt_token_count=10),
            candidates=[SimpleNamespace(content=SimpleNamespace(parts=[]))],
            function_calls=[call],
            text=None,
        )

    monkeypatch.setattr(agent_core, "call_llm", fake_call_llm)
    result = run_agent("x", tools=[add], system_instruction="x", max_steps=4, verbose=False)
    assert result.stop_reason == "max_steps"
    assert result.prompt_tokens_per_step == [10, 10, 10, 10]
