"""Offline evaluation of the guardrail stack.

Measures, on labelled data:
  * Stage 1 PII engine  - per-entity precision/recall + latency           (data/pii_cases.jsonl)
  * Keyword blacklist   - the naive heuristic defence Perez & Ribeiro warn about
  * Stage 2 DeBERTa-v3  - precision/recall/F1/FPR at tau, threshold sweep, per-category
                          detection rate, CPU latency P50/P95/P99   (data/eval_prompts.jsonl)

Usage:
  python scripts/evaluate.py                 # full run (downloads the DeBERTa model once, ~740 MB)
  python scripts/evaluate.py --no-model      # PII + keyword baseline only (no torch needed)
Outputs go to results/: metrics.json, RESULTS.md, per_prompt_scores.csv and PNG charts.
"""
from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway.pii import redact  # noqa: E402

# A typical hand-written blacklist of the kind found in many early LLM apps.
KEYWORD_BLACKLIST = [
    "ignore previous instructions", "ignore all previous", "ignore the previous", "ignore any previous",
    "ignore the above", "disregard the instructions", "system prompt", "you are now", "jailbreak",
    "developer mode", "do anything now", "reveal your prompt", "print your instructions",
]


def keyword_flag(text: str) -> int:
    t = " ".join(text.lower().split())
    return int(any(k in t for k in KEYWORD_BLACKLIST))


def pct(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def lat_summary(ms: list[float]) -> dict:
    return {"n": len(ms), "mean": round(statistics.fmean(ms), 3), "p50": round(pct(ms, .50), 3),
            "p95": round(pct(ms, .95), 3), "p99": round(pct(ms, .99), 3), "max": round(max(ms), 3)}


def binary_metrics(y: list[int], yhat: list[int]) -> dict:
    tp = sum(1 for a, b in zip(y, yhat) if a == 1 and b == 1)
    tn = sum(1 for a, b in zip(y, yhat) if a == 0 and b == 0)
    fp = sum(1 for a, b in zip(y, yhat) if a == 0 and b == 1)
    fn = sum(1 for a, b in zip(y, yhat) if a == 1 and b == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "accuracy": round((tp + tn) / len(y), 4),
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0}


def per_category(rows, preds) -> dict:
    agg = defaultdict(lambda: [0, 0])
    for r, p in zip(rows, preds):
        agg[r["category"]][0] += int(p == r["label"])
        agg[r["category"]][1] += 1
    return {c: {"correct": a, "total": n, "rate": round(a / n, 3)} for c, (a, n) in sorted(agg.items())}


def eval_pii(cases: list[dict], repeats: int) -> dict:
    tp, fp, fn = Counter(), Counter(), Counter()
    lat = []
    for c in cases:
        _, found = redact(c["text"])
        exp = Counter(c["expected"])
        for k in set(found) | set(exp):
            tp[k] += min(found[k], exp[k])
            fp[k] += max(found[k] - exp[k], 0)
            fn[k] += max(exp[k] - found[k], 0)
        for _ in range(repeats):
            t = time.perf_counter()
            redact(c["text"])
            lat.append((time.perf_counter() - t) * 1000)
    per_type = {}
    for k in sorted(set(tp) | set(fp) | set(fn)):
        p = tp[k] / (tp[k] + fp[k]) if tp[k] + fp[k] else 0.0
        r = tp[k] / (tp[k] + fn[k]) if tp[k] + fn[k] else 0.0
        per_type[k] = {"tp": tp[k], "fp": fp[k], "fn": fn[k], "precision": round(p, 3), "recall": round(r, 3)}
    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    return {"cases": len(cases), "per_type": per_type,
            "micro_precision": round(T / (T + F), 4) if T + F else 0.0,
            "micro_recall": round(T / (T + N), 4) if T + N else 0.0,
            "latency_ms": lat_summary(lat)}


def charts(out: Path, res: dict, rows, scores, pii_lat, guard_lat) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    made = []
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.hist(pii_lat, bins=40, color="#2E7D6B")
    ax.set(title="Stage 1 PII engine latency per prompt (CPU)", xlabel="ms", ylabel="count")
    fig.tight_layout(); fig.savefig(out / "pii_latency_hist.png", dpi=150); plt.close(fig)
    made.append("pii_latency_hist.png")

    cats = list(res["keyword_baseline"]["per_category"].keys())
    kw = [res["keyword_baseline"]["per_category"][c]["rate"] for c in cats]
    fig, ax = plt.subplots(figsize=(9, 4))
    x = range(len(cats))
    if scores is not None:
        db = [res["deberta"]["per_category"][c]["rate"] for c in cats]
        ax.bar([i - 0.2 for i in x], kw, 0.4, label="Keyword blacklist", color="#B0BEC5")
        ax.bar([i + 0.2 for i in x], db, 0.4, label=f"DeBERTa-v3 (tau={res['threshold']})", color="#1565C0")
    else:
        ax.bar(list(x), kw, 0.5, label="Keyword blacklist", color="#B0BEC5")
    ax.set_xticks(list(x)); ax.set_xticklabels(cats, rotation=30, ha="right", fontsize=8)
    ax.set(ylim=(0, 1.05), ylabel="correct-decision rate", title="Correct decisions by prompt category")
    ax.legend(fontsize=8); fig.tight_layout(); fig.savefig(out / "category_accuracy.png", dpi=150); plt.close(fig)
    made.append("category_accuracy.png")

    if scores is not None:
        sweep = res["deberta"]["threshold_sweep"]
        fig, ax = plt.subplots(figsize=(7, 3.8))
        ts = [s["threshold"] for s in sweep]
        for key, col in (("precision", "#1565C0"), ("recall", "#C62828"), ("f1", "#2E7D32"), ("fpr", "#757575")):
            ax.plot(ts, [s[key] for s in sweep], label=key, color=col)
        ax.axvline(res["threshold"], ls="--", color="black", lw=1)
        ax.set(xlabel="threshold tau", ylim=(0, 1.05), title="DeBERTa-v3 threshold sweep")
        ax.legend(fontsize=8); fig.tight_layout(); fig.savefig(out / "threshold_sweep.png", dpi=150); plt.close(fig)
        made.append("threshold_sweep.png")

        fig, ax = plt.subplots(figsize=(7, 3.6))
        ax.hist(guard_lat, bins=40, color="#1565C0")
        ax.set(title="Stage 2 DeBERTa-v3 latency per prompt (CPU)", xlabel="ms", ylabel="count")
        fig.tight_layout(); fig.savefig(out / "guardrail_latency_hist.png", dpi=150); plt.close(fig)
        made.append("guardrail_latency_hist.png")

        fig, ax = plt.subplots(figsize=(7, 3.6))
        ben = [s for s, r in zip(scores, rows) if r["label"] == 0]
        inj = [s for s, r in zip(scores, rows) if r["label"] == 1]
        ax.hist([ben, inj], bins=20, range=(0, 1), label=["benign", "injection"], color=["#2E7D32", "#C62828"])
        ax.axvline(res["threshold"], ls="--", color="black", lw=1)
        ax.set(title="P(injection) distribution by true label", xlabel="score", ylabel="count")
        ax.legend(fontsize=8); fig.tight_layout(); fig.savefig(out / "score_distribution.png", dpi=150); plt.close(fig)
        made.append("score_distribution.png")
    return made


def write_markdown(out: Path, res: dict) -> None:
    L = [f"# Evaluation results\n", f"Generated: {res['generated_at']}  |  Host: {res['host']}\n"]
    p = res["pii"]
    L += ["## Stage 1 - PII engine\n", f"{p['cases']} labelled cases; micro precision **{p['micro_precision']}**, "
          f"micro recall **{p['micro_recall']}**. Latency p50 {p['latency_ms']['p50']} ms, "
          f"p95 {p['latency_ms']['p95']} ms.\n", "| Entity | TP | FP | FN | Precision | Recall |",
          "|---|---|---|---|---|---|"]
    L += [f"| {k} | {v['tp']} | {v['fp']} | {v['fn']} | {v['precision']} | {v['recall']} |" for k, v in p["per_type"].items()]
    L += ["", f"## Injection detection on {res['n_prompts']} prompts ({res['n_injections']} injections)\n",
          "| Detector | Accuracy | Precision | Recall | F1 | FPR | TP | FP | TN | FN |", "|---|---|---|---|---|---|---|---|---|---|"]
    for name, key in (("Keyword blacklist", "keyword_baseline"), (f"DeBERTa-v3 (tau={res['threshold']})", "deberta")):
        if key in res:
            m = res[key]["metrics"]
            L.append(f"| {name} | {m['accuracy']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['fpr']} | "
                     f"{m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |")
    L += ["", "### Correct-decision rate by category\n", "| Category | Keyword | DeBERTa-v3 |", "|---|---|---|"]
    for c, v in res["keyword_baseline"]["per_category"].items():
        d = res.get("deberta", {}).get("per_category", {}).get(c, {})
        L.append(f"| {c} | {v['correct']}/{v['total']} | {str(d.get('correct', '-')) + '/' + str(d.get('total', '-')) if d else '-'} |")
    if "deberta" in res:
        g = res["deberta"]["latency_ms"]
        L += ["", "## Stage 2 latency (CPU, one prompt per call)\n",
              f"mean {g['mean']} ms, p50 {g['p50']} ms, **p95 {g['p95']} ms**, p99 {g['p99']} ms\n",
              f"Total guardrail overhead p95 (Stage 1 + Stage 2): **{res['guardrail_overhead_p95_ms']} ms**\n"]
    (out / "RESULTS.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "data/eval_prompts.jsonl"))
    ap.add_argument("--pii-data", default=str(ROOT / "data/pii_cases.jsonl"))
    ap.add_argument("--threshold", type=float, default=0.85)
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--no-model", action="store_true", help="skip DeBERTa (no torch required)")
    ap.add_argument("--repeats", type=int, default=3, help="latency repetitions per prompt")
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(l) for l in Path(a.data).read_text(encoding="utf-8").splitlines() if l.strip()]
    pii_cases = [json.loads(l) for l in Path(a.pii_data).read_text(encoding="utf-8").splitlines() if l.strip()]
    y = [r["label"] for r in rows]

    res = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "threshold": a.threshold,
           "host": f"{platform.system()} {platform.machine()} | {platform.processor() or 'cpu'} | Python {platform.python_version()}",
           "n_prompts": len(rows), "n_injections": sum(y)}
    res["pii"] = eval_pii(pii_cases, repeats=max(a.repeats * 10, 30))

    sanitized, pii_lat = [], []
    for r in rows:
        for _ in range(max(1, a.repeats)):
            t = time.perf_counter(); text, _ = redact(r["text"]); pii_lat.append((time.perf_counter() - t) * 1000)
        sanitized.append(text)
    kw = [keyword_flag(t) for t in sanitized]
    res["keyword_baseline"] = {"metrics": binary_metrics(y, kw), "per_category": per_category(rows, kw)}

    scores, guard_lat = None, []
    if not a.no_model:
        from gateway.guardrail import InjectionGuardrail
        print("Loading DeBERTa-v3 guardrail (first run downloads the model)...")
        guard = InjectionGuardrail()
        res["guard_model"] = guard.model_id
        scores = []
        for t in sanitized:
            for _ in range(max(1, a.repeats)):
                t0 = time.perf_counter(); s = guard.score(t); guard_lat.append((time.perf_counter() - t0) * 1000)
            scores.append(s)
        preds = [int(s > a.threshold) for s in scores]
        sweep = []
        for i in range(1, 100):
            th = i / 100
            m = binary_metrics(y, [int(s > th) for s in scores])
            sweep.append({"threshold": th, **{k: m[k] for k in ("precision", "recall", "f1", "fpr")}})
        res["deberta"] = {"metrics": binary_metrics(y, preds), "per_category": per_category(rows, preds),
                          "latency_ms": lat_summary(guard_lat), "threshold_sweep": sweep}
        overhead = [p + g for p, g in zip(pii_lat, guard_lat)]
        res["guardrail_overhead_p95_ms"] = round(pct(overhead, .95), 3)

    with (out / "per_prompt_scores.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "category", "label", "keyword_flag", "deberta_score", "deberta_pred", "text"])
        for i, r in enumerate(rows):
            s = scores[i] if scores is not None else ""
            w.writerow([r["id"], r["category"], r["label"], kw[i], f"{s:.4f}" if s != "" else "",
                        int(s > a.threshold) if s != "" else "", r["text"][:200]])
    res["pii_latency_ms"] = lat_summary(pii_lat)
    res["charts"] = charts(out, res, rows, scores, pii_lat, guard_lat)
    (out / "metrics.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    write_markdown(out, res)
    print((out / "RESULTS.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
