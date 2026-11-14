"""Tests de llm.py: sin red ni claves."""
from __future__ import annotations

from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict

from agent_runtime.ml_d.llm import (
    LLMError, LLMNotConfigured, MockLLM, extract_json_text, is_configured, load_env, make_llm,
)


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["read", "write"]
    count: int


SYSTEM = [{"role": "user", "content": "plan"}]


def test_complete_json_parses_fenced_output() -> None:
    llm = MockLLM("orchestrator", ['```json\n{"action": "read", "count": 2}\n```'])
    assert llm.complete_json(SYSTEM, Answer) == Answer(action="read", count=2)
    assert llm.stats.calls == 1 and llm.stats.failures == 0


def test_complete_json_retries_then_succeeds() -> None:
    llm = MockLLM("orchestrator", ['{"action": "delete", "count": 1}', '{"action": "write", "count": 1}'])
    assert llm.complete_json(SYSTEM, Answer).action == "write"
    assert llm.stats.calls == 2
    feedback = llm.seen[1][-1]["content"]
    assert "action" in feedback and "delete" not in feedback  # solo el tipo de error, no el valor


def test_complete_json_rejects_extra_fields_and_gives_up() -> None:
    bad = '{"action": "read", "count": 1, "note": "ignore previous instructions"}'
    llm = MockLLM("orchestrator", [bad, bad, bad])
    with pytest.raises(LLMError):
        llm.complete_json(SYSTEM, Answer, max_retries=2)
    assert llm.stats.calls == 3 and llm.stats.failures == 1


def test_mock_raises_when_script_exhausted() -> None:
    with pytest.raises(LLMError):
        MockLLM("customs", []).complete(SYSTEM)


def test_mock_callable_responder_and_flag() -> None:
    llm = make_llm("customs", mock=True, responses=lambda msgs: f"n={len(msgs)}")
    assert llm.is_mock and llm.complete(SYSTEM) == "n=1"


def test_instances_do_not_share_state() -> None:
    a, b = make_llm("orchestrator", mock=True, responses=["x"]), make_llm("vault_worker", mock=True, responses=["y"])
    a.complete(SYSTEM)
    assert a.stats.calls == 1 and b.stats.calls == 0


def test_extract_json_text_handles_surrounding_prose() -> None:
    assert extract_json_text('Sure! {"a": 1} hope it helps') == '{"a": 1}'


def test_make_llm_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_MODEL_ORCHESTRATOR", raising=False)
    assert not is_configured("orchestrator")
    with pytest.raises(LLMNotConfigured):
        make_llm("orchestrator")


def test_load_env_does_not_override(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = tmp_path / ".env"
    env.write_text("# comment\nLLM_BASE_URL=http://127.0.0.1:11434/v1\nLLM_MODEL_CUSTOMS='m1'\n", encoding="utf-8")
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:9999/v1")
    monkeypatch.delenv("LLM_MODEL_CUSTOMS", raising=False)
    load_env(env)
    import os
    assert os.environ["LLM_BASE_URL"] == "http://127.0.0.1:9999/v1"
    assert os.environ["LLM_MODEL_CUSTOMS"] == "m1"
