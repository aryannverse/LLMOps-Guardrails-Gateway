# Evaluation results

Generated: 2026-10-31 21:16:43  |  Host: Darwin arm64 | arm | Python 3.12.4

## Stage 1 - PII engine

30 labelled cases; micro precision **1.0**, micro recall **1.0**. Latency p50 0.005 ms, p95 0.01 ms.

| Entity | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| AADHAAR | 3 | 0 | 0 | 1.0 | 1.0 |
| API_KEY | 4 | 0 | 0 | 1.0 | 1.0 |
| CREDIT_CARD | 5 | 0 | 0 | 1.0 | 1.0 |
| EMAIL | 5 | 0 | 0 | 1.0 | 1.0 |
| PAN | 2 | 0 | 0 | 1.0 | 1.0 |
| PHONE | 6 | 0 | 0 | 1.0 | 1.0 |
| SSN | 1 | 0 | 0 | 1.0 | 1.0 |

## Injection detection on 82 prompts (48 injections)

| Detector | Accuracy | Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|---|
| Keyword blacklist | 0.5366 | 0.8125 | 0.2708 | 0.4062 | 0.0882 | 13 | 3 | 31 | 35 |
| DeBERTa-v3 (tau=0.85) | 0.8659 | 0.8936 | 0.875 | 0.8842 | 0.1471 | 42 | 5 | 29 | 6 |

### Correct-decision rate by category

| Category | Keyword | DeBERTa-v3 |
|---|---|---|
| benign_general | 14/14 | 14/14 |
| benign_hard_negative | 11/14 | 12/14 |
| benign_with_pii | 6/6 | 3/6 |
| goal_hijacking | 3/12 | 12/12 |
| indirect_injection | 1/10 | 5/10 |
| multilingual | 1/6 | 6/6 |
| obfuscated | 2/6 | 6/6 |
| prompt_leaking | 3/8 | 8/8 |
| roleplay_jailbreak | 3/6 | 5/6 |

## Stage 2 latency (CPU, one prompt per call)

mean 64.003 ms, p50 64.017 ms, **p95 69.153 ms**, p99 72.29 ms

Total guardrail overhead p95 (Stage 1 + Stage 2): **69.163 ms**

