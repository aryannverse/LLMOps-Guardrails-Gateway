"""/secure-chat - Dual-layer zero-trust LLMOps security gateway (FastAPI).

Request flow:  Stage 1 PII redaction -> Stage 2 DeBERTa injection guardrail
               -> (blocked: HTTP 403) or (allowed: Groq LLM) -> hash-chained telemetry.
Run:  uvicorn gateway.main:app --port 8000
"""
from __future__ import annotations

import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .pii import redact
from .telemetry import TelemetryLog

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
THRESHOLD = float(os.getenv("INJECTION_THRESHOLD", "0.85"))
_log_path = Path(os.getenv("TELEMETRY_PATH", "logs/telemetry.jsonl"))
TELEMETRY_PATH = _log_path if _log_path.is_absolute() else ROOT / _log_path  # same file the dashboard reads
PREVIEW_CHARS = int(os.getenv("LOG_PREVIEW_CHARS", "160"))


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20_000)
    context: list[str] = Field(default_factory=list, max_length=8,
                               description="Retrieved documents (RAG chunks, web pages, emails): "
                                           "the indirect prompt-injection surface.")


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def create_app(guard=None, llm=None, log=None, threshold: float = THRESHOLD) -> FastAPI:
    """Factory so tests can inject lightweight fakes; production loads the real components."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if guard is None:  # heavy imports (torch/transformers, groq) only when actually needed
            from .guardrail import InjectionGuardrail
            app.state.guard = InjectionGuardrail()
        else:
            app.state.guard = guard
        if llm is None:
            from .llm import GroqLLM
            app.state.llm = GroqLLM()
        else:
            app.state.llm = llm
        app.state.log = log if log is not None else TelemetryLog(TELEMETRY_PATH)
        yield

    app = FastAPI(title="LLMOps Security & Guardrail Gateway", version="1.0.0", lifespan=lifespan)

    @app.get("/health")
    def health(request: Request):
        s = request.app.state
        return {"status": "ok", "guard_model": getattr(s.guard, "model_id", "unknown"),
                "llm_model": getattr(s.llm, "model", "unknown"), "threshold": threshold}

    @app.post("/secure-chat")
    def secure_chat(req: ChatRequest, request: Request):  # sync def -> runs in FastAPI's threadpool
        s, rid, t0 = request.app.state, uuid.uuid4().hex[:12], time.perf_counter()

        # Stage 1: deterministic PII sanitisation. Raw text is never used after this block.
        clean_prompt, pii = redact(req.prompt)
        clean_ctx = []
        for doc in req.context:
            text, found = redact(doc)
            clean_ctx.append(text)
            pii.update(found)
        pii_ms = _ms(t0)

        # Stage 2: semantic injection classifier over the prompt AND every retrieved document.
        t1, error = time.perf_counter(), None
        try:
            scores = s.guard.score_many([clean_prompt, *clean_ctx])
        except Exception as exc:  # fail closed: a broken guardrail must never let traffic through
            scores, error = [1.0], f"guardrail_error:{type(exc).__name__}"
        guard_ms = _ms(t1)
        top = max(range(len(scores)), key=scores.__getitem__)
        score, source = scores[top], ("prompt" if top == 0 else f"context[{top - 1}]")

        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "request_id": rid, "injection_score": round(score, 4), "threshold": threshold,
            "flagged_source": source, "pii_counts": dict(pii), "pii_total": sum(pii.values()),
            "n_context_docs": len(clean_ctx), "prompt_chars": len(req.prompt),
            "prompt_preview": clean_prompt[:PREVIEW_CHARS], "error": error,
            "latency_ms": {"pii": pii_ms, "guardrail": guard_ms,
                           "guardrail_overhead": round(pii_ms + guard_ms, 3)},
        }

        if score > threshold:
            record["latency_ms"]["total"] = _ms(t0)
            s.log.append({**record, "decision": "BLOCKED"})
            return JSONResponse(status_code=403, content={
                "detail": "Request blocked by the prompt-injection guardrail.", "request_id": rid,
                "injection_score": record["injection_score"], "threshold": threshold,
                "flagged_source": source, "pii_redacted": dict(pii)})

        # Stage 3: only sanitised, approved text is forwarded to the external LLM (Groq).
        t2 = time.perf_counter()
        try:
            answer, usage = s.llm.complete(clean_prompt, clean_ctx)
        except Exception as exc:
            record["latency_ms"].update(llm=_ms(t2), total=_ms(t0))
            s.log.append({**record, "decision": "LLM_ERROR", "error": f"llm_error:{type(exc).__name__}"})
            return JSONResponse(status_code=502, content={"detail": "Upstream LLM call failed.",
                                                          "request_id": rid})
        record["latency_ms"].update(llm=_ms(t2), total=_ms(t0))
        s.log.append({**record, "decision": "ALLOWED", "llm_model": getattr(s.llm, "model", None),
                      "llm_usage": usage})
        return {"request_id": rid, "response": answer, "sanitized_prompt": clean_prompt,
                "pii_redacted": dict(pii), "model": getattr(s.llm, "model", None),
                "guardrail": {"injection_score": record["injection_score"], "threshold": threshold,
                              "latency_ms": record["latency_ms"]}}

    return app


app = create_app()
