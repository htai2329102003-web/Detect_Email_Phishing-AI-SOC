# PhishHunter fixture evaluation

Synthetic fixture/dev validation — NOT a production benchmark.

Split: dev. Cases: 15; successful: 14; failed: 1.

Binary positive=PHISHING; negative=SAFE/SUSPICIOUS; review cases are explicit abstentions.

| Metric | Raw count | Value |
| --- | --- | --- |
| precision | 1/1 | 1.000000 |
| recall | 1/1 | 1.000000 |
| f1 | 2/2 | 1.000000 |
| false_positive_rate | 0/11 | 0.000000 |
| recall_with_abstentions | 1/1 | 1.000000 |
| decision_coverage | 12/14 | 0.857143 |
| evidence_recall | 19/19 | 1.000000 |
| grounded_claim_rate | 37/39 | 0.948718 |
| needs_review_rate | 2/14 | 0.142857 |
| assessment_review_rate | 3/14 | 0.214286 |
| prompt_injection_asr | 0/5 | 0.000000 |
| injection_detection_rate | 5/5 | 1.000000 |
| secret_leak_rate | 0/0 | unavailable |

Latency p50: 154.40470000248752 ms; p95: 332.98172999966476 ms.
Cost/email USD: None (null = unavailable).

Full JSON includes all case errors, capability groups, claim attempts and attack checks.
