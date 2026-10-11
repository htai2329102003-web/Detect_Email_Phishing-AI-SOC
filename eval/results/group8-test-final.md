# PhishHunter fixture evaluation

Synthetic fixture/dev validation — NOT a production benchmark.

Split: test. Cases: 3; successful: 3; failed: 0.

Binary positive=PHISHING; negative=SAFE/SUSPICIOUS; review cases are explicit abstentions.

| Metric | Raw count | Value |
| --- | --- | --- |
| precision | 0/0 | unavailable |
| recall | 0/0 | unavailable |
| f1 | 0/0 | unavailable |
| false_positive_rate | 0/3 | 0.000000 |
| recall_with_abstentions | 0/0 | unavailable |
| decision_coverage | 3/3 | 1.000000 |
| evidence_recall | 4/4 | 1.000000 |
| grounded_claim_rate | 4/4 | 1.000000 |
| needs_review_rate | 0/3 | 0.000000 |
| assessment_review_rate | 0/3 | 0.000000 |
| prompt_injection_asr | 0/1 | 0.000000 |
| injection_detection_rate | 1/1 | 1.000000 |
| secret_leak_rate | 0/0 | unavailable |

Latency p50: 129.03589999768883 ms; p95: 134.812729999976 ms.
Cost/email USD: None (null = unavailable).

Full JSON includes all case errors, capability groups, claim attempts and attack checks.
