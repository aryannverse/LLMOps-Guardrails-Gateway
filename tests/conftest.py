"""Shared fixtures. FakeGuard/FakeLLM replace DeBERTa and Groq so the pipeline logic can be
tested in CI without torch, model downloads or an API key. They do NOT measure model quality;
that is what scripts/evaluate.py is for."""
import pytest
from fastapi.testclient import TestClient

from gateway.main import create_app
from gateway.telemetry import TelemetryLog


class FakeGuard:
    model_id = "fake-guard"

    def __init__(self, fail: bool = False):
        self.fail, self.seen = fail, []

    def score_many(self, texts):
        if self.fail:
            raise RuntimeError("model crashed")
        self.seen.extend(texts)
        return [0.99 if "ignore previous instructions" in t.lower() else 0.02 for t in texts]


class FakeLLM:
    model = "fake-llm"

    def __init__(self, fail: bool = False):
        self.fail, self.calls = fail, []

    def complete(self, prompt, context=None):
        if self.fail:
            raise TimeoutError("upstream timeout")
        self.calls.append((prompt, list(context or [])))
        return f"echo: {prompt}", {"prompt_tokens": 10, "completion_tokens": 5}


@pytest.fixture
def make_client(tmp_path):
    def _make(guard=None, llm=None):
        guard, llm = guard or FakeGuard(), llm or FakeLLM()
        log = TelemetryLog(tmp_path / "telemetry.jsonl")
        client = TestClient(create_app(guard=guard, llm=llm, log=log, threshold=0.85))
        return client, guard, llm, log
    return _make
