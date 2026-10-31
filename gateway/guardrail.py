"""Stage 2 - Semantic prompt-injection guardrail (DeBERTa-v3 encoder on CPU).

Scores each text with P(injection | sanitised text). DeBERTa accepts at most 512
tokens, so long inputs are split into overlapping windows and the maximum window
score is kept; otherwise an attacker could pad a prompt and hide the payload
beyond the truncation point.
"""
from __future__ import annotations

import os

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


class InjectionGuardrail:
    def __init__(self, model_id: str | None = None, max_length: int = 512, stride: int = 128,
                 threads: int | None = None) -> None:
        import torch  # imported lazily so the rest of the gateway (and CI tests) run without torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.model_id = model_id or os.getenv("GUARD_MODEL_ID", DEFAULT_MODEL)
        threads = threads or int(os.getenv("TORCH_THREADS", "0"))
        if threads:
            torch.set_num_threads(threads)
        self._torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id, use_fast=True)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_id).eval()
        labels = {str(v).upper(): int(k) for k, v in self.model.config.id2label.items()}
        self.injection_index = labels.get("INJECTION", 1)  # model card: 0 = benign, 1 = injection
        self.max_length, self.stride = max_length, stride
        self.score_many(["warm-up request"])  # first call is slow; keep it out of request latency

    def score_many(self, texts: list[str]) -> list[float]:
        """Return one injection probability per input text (max over its windows)."""
        if not texts:
            return []
        enc = self.tokenizer(texts, truncation=True, max_length=self.max_length, stride=self.stride,
                             return_overflowing_tokens=True, padding=True, return_tensors="pt")
        owner = enc.pop("overflow_to_sample_mapping").tolist()
        with self._torch.inference_mode():
            probs = self.model(**enc).logits.softmax(dim=-1)[:, self.injection_index].tolist()
        scores = [0.0] * len(texts)
        for i, p in zip(owner, probs):
            scores[i] = max(scores[i], p)
        return scores

    def score(self, text: str) -> float:
        return self.score_many([text])[0]
