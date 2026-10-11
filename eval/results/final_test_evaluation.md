# Final TEST recovery evaluation

**Recovery pass purpose: metric capture only.** The first inference pass is retained as an unscorable failed aggregation attempt.

## Integrity

- Initial TEST pass: UNSCORABLE — evaluation runner aggregation bug
- Config changed after initial pass: NO
- TEST metrics observed before recovery: NO
- TEST used for tuning: NO
- Total TEST inference passes: 2
- Valid scored TEST passes: 1
- Frozen R2-F config verified: YES

## Frozen config

- PHISHING / SUSPICIOUS thresholds: 62.0 / 30.0
- URL_IP_LITERAL / IOC_DERIVED_DOMAIN: 0.55 / 0.2

## TEST

- Canonical / Defender skipped / attempted: 1028 / 4 / 1024
- Successful / execution errors: 1024 / 0
- SAFE / SUSPICIOUS / PHISHING / REVIEW: 0 / 169 / 71 / 784
- TP / TN / FP / FN: 71 / 88 / 0 / 81

## Metrics (DEV → TEST)

- Phishing recall: 26.1299% → 25.0883% (71/283)
- SAFE FPR: 0.2545% → 0.0000% (0/741)
- Precision: 96.3542% → 100.0000% (71/71)
- Decision coverage: 24.7396% → 23.4375% (240/1024)
- Abstention: 75.2604% → 76.5625% (784/1024)

## Cost and scope

- BEC / Verdict LLM / RAG / VT / urlscan calls: 0 / 0 / 0 / 0 / 0
- No tuning, DEV rerun, production changes, config changes, or data changes.
- The four quarantined E2A rows were excluded by ID without opening their message files.

**Final TEST complete: YES**
**Final config remains R2-F: YES**
**Ready for G9 / final delivery: YES**
