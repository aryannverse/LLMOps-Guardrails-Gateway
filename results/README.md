# results/

* `no_model_baseline/` - produced during development with `python scripts/evaluate.py --no-model --repeats 20`
  (Linux x86_64 container, Python 3.12). Contains real measurements of the Stage 1 PII engine and of the
  keyword-blacklist baseline. It has no DeBERTa numbers because the model could not be downloaded there.
* `test_report.txt` - verbose output of `pytest -v` from the same environment (44 passed).

Running `python scripts/evaluate.py` on your machine writes the full results (including DeBERTa-v3 accuracy,
threshold sweep and CPU latency) directly into this folder: `RESULTS.md`, `metrics.json`, charts.
