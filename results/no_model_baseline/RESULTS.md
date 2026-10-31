# Evaluation results

Generated: 2026-10-31 12:16:11  |  Host: Linux x86_64 | x86_64 | Python 3.12.3

## Stage 1 - PII engine

30 labelled cases; micro precision **1.0**, micro recall **1.0**. Latency p50 0.01 ms, p95 0.028 ms.

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

### Correct-decision rate by category

| Category | Keyword | DeBERTa-v3 |
|---|---|---|
| benign_general | 14/14 | - |
| benign_hard_negative | 11/14 | - |
| benign_with_pii | 6/6 | - |
| goal_hijacking | 3/12 | - |
| indirect_injection | 1/10 | - |
| multilingual | 1/6 | - |
| obfuscated | 2/6 | - |
| prompt_leaking | 3/8 | - |
| roleplay_jailbreak | 3/6 | - |
