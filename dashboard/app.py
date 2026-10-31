"""Stage 3 - MLOps observability dashboard for the guardrail gateway.

Reads the hash-chained telemetry log written by the gateway and refreshes live.
Run:  streamlit run dashboard/app.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway.telemetry import verify_chain  # noqa: E402

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

LOG_PATH = Path(os.getenv("TELEMETRY_PATH", "logs/telemetry.jsonl"))
if not LOG_PATH.is_absolute():
    LOG_PATH = ROOT / LOG_PATH
DECISION_COLORS = alt.Scale(domain=["ALLOWED", "BLOCKED", "LLM_ERROR"], range=["#2E7D32", "#C62828", "#F9A825"])

st.set_page_config(page_title="LLMOps Guardrail Monitor", page_icon="🛡️", layout="wide")


def load(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not rows:
        return pd.DataFrame()
    df = pd.json_normalize(rows)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df.sort_values("ts")


st.title("🛡️ LLMOps Security & Guardrail Gateway: Live Monitor")
st.caption(f"Telemetry source: `{LOG_PATH}`")
refresh = st.sidebar.slider("Auto-refresh every (seconds, 0 = off)", 0, 30, 5)
window = st.sidebar.selectbox("Time window", ["All", "Last 15 min", "Last 1 h", "Last 24 h"])


@st.fragment(run_every=refresh if refresh else None)
def render() -> None:
    df = load(LOG_PATH)
    if df.empty:
        st.info("No telemetry yet. Start the gateway and send traffic with `python scripts/attack_suite.py`.")
        return
    if window != "All":
        delta = {"Last 15 min": "15min", "Last 1 h": "1h", "Last 24 h": "24h"}[window]
        df = df[df["ts"] >= pd.Timestamp.now(tz="UTC") - pd.Timedelta(delta)]
        if df.empty:
            st.info("No requests in the selected window.")
            return

    total = len(df)
    blocked = int((df["decision"] == "BLOCKED").sum())
    pii_total = int(df["pii_total"].sum())
    overhead = df["latency_ms.guardrail_overhead"]
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total requests", f"{total:,}")
    c2.metric("Blocked attacks", f"{blocked:,}", f"{blocked / total:.1%} of traffic", delta_color="off")
    c3.metric("PII entities redacted", f"{pii_total:,}")
    c4.metric("P95 guardrail overhead", f"{overhead.quantile(0.95):.1f} ms", f"P50 {overhead.median():.1f} ms",
              delta_color="off")
    if "latency_ms.llm" in df and df["latency_ms.llm"].notna().any():
        c5.metric("P50 LLM latency (Groq)", f"{df['latency_ms.llm'].median():.0f} ms")
    else:
        c5.metric("P50 LLM latency (Groq)", "n/a")

    ok, n, bad = verify_chain(LOG_PATH)
    if ok:
        st.success(f"Audit-log hash chain verified: {n} records, no tampering detected.")
    else:
        st.error(f"Audit-log integrity FAILED at line {bad + 1} (after {n} valid records).")

    left, right = st.columns(2)
    per_min = df.set_index("ts").groupby("decision").resample("1min").size().reset_index(name="requests")
    left.subheader("Requests per minute by decision")
    left.altair_chart(alt.Chart(per_min).mark_bar().encode(
        x=alt.X("ts:T", title="time (UTC)"), y=alt.Y("requests:Q", stack=True),
        color=alt.Color("decision:N", scale=DECISION_COLORS)), width="stretch")

    right.subheader("Injection-score distribution")
    thr = float(df["threshold"].iloc[-1])
    hist = alt.Chart(df).mark_bar(opacity=0.85).encode(
        x=alt.X("injection_score:Q", bin=alt.Bin(maxbins=25), title="P(injection)"),
        y=alt.Y("count():Q", title="requests"), color=alt.Color("decision:N", scale=DECISION_COLORS))
    rule = alt.Chart(pd.DataFrame({"t": [thr]})).mark_rule(strokeDash=[6, 4], color="black").encode(x="t:Q")
    right.altair_chart(hist + rule, width="stretch")

    left2, right2 = st.columns(2)
    left2.subheader("Guardrail overhead per request (ms)")
    lat = df[["ts", "latency_ms.pii", "latency_ms.guardrail"]].rename(
        columns={"latency_ms.pii": "Stage 1 PII", "latency_ms.guardrail": "Stage 2 DeBERTa"}).melt("ts")
    left2.altair_chart(alt.Chart(lat).mark_line(point=True).encode(
        x=alt.X("ts:T", title="time (UTC)"), y=alt.Y("value:Q", title="ms"), color="variable:N"),
        width="stretch")

    right2.subheader("PII entities redacted by type")
    pii_cols = [c for c in df.columns if c.startswith("pii_counts.")]
    if pii_cols:
        pii = df[pii_cols].sum().rename(lambda c: c.split(".", 1)[1]).reset_index()
        pii.columns = ["entity", "count"]
        right2.altair_chart(alt.Chart(pii).mark_bar(color="#1565C0").encode(
            x=alt.X("count:Q"), y=alt.Y("entity:N", sort="-x")), width="stretch")
    else:
        right2.info("No PII redacted yet.")

    st.subheader("Live audit trail (newest first)")
    table = df.sort_values("ts", ascending=False)[[
        "ts", "request_id", "decision", "injection_score", "flagged_source", "pii_total",
        "latency_ms.guardrail_overhead", "latency_ms.total", "prompt_preview", "hash"]].rename(columns={
        "latency_ms.guardrail_overhead": "guard_ms", "latency_ms.total": "total_ms", "hash": "record_hash"})
    table["record_hash"] = table["record_hash"].str[:12] + "…"
    st.dataframe(table.style.apply(lambda r: ["background-color: rgba(198,40,40,0.15)"] * len(r)
                                   if r["decision"] == "BLOCKED" else [""] * len(r), axis=1),
                 width="stretch", hide_index=True, height=420)


render()
