# PhishHunter DEV baseline v1.1.1

Execution measurement complete; detection-quality baseline blocked.

- Canonical: 3,462 (2,750 SAFE, 712 PHISHING).
- Attempted: 3,458 (99.88446% canonical coverage); quarantine skipped: 4; other skipped: 0.
- Successful predictions: 3,308; Parser rejections: 150 (37 SAFE, 113 PHISHING).
- All successful native predictions: NEEDS_ANALYST_REVIEW. No forced binary mapping.
- Selective binary TP/TN/FP/FN: 0/0/0/0; precision, recall, F1, accuracy, FPR, FNR: NULL (zero eligible decisions).
- Positive abstentions: 595; abstention/error-inclusive recall: 0/708.
- Required SPF/DKIM/DMARC signals UNKNOWN in all 3,308 successful cases; trusted authserv IDs unconfigured.
- Parser codes: MALFORMED_HEADER 100; DUPLICATE_HEADER 30; INVALID_ADDRESS 10; MALFORMED_EMAIL 9; INVALID_FROM 1.
- One QR_DECODE_FAILED tool error; not mapped to SAFE.
- Explicit evidence oracle cases: 0; evidence recall/precision NULL.
- Gate 2 grounded candidate claims: 15,022/15,022.
- Auth-header DEV: 121 attempted, 90 UNKNOWN, 31 Parser errors; known-evidence coverage 349/630.
- Attachment DEV: 181 attempted, 177 OK, 4 Parser errors; known-evidence coverage 551/551 on successful cases.
- Vietnamese URL, BEC, QR: NO_DEV_SPLIT; 0 executed.
- Prompt injection: ORACLE_INSUFFICIENT; 0 executed; ASR NULL, denominator 0.
- IOC available; 32,474 local lookups (CORE + capabilities); 0 lookup errors.
- Qdrant green, 1,161 chunk points + 1 manifest; RAG disabled by current graph settings; 0 retrieval calls.
- External enrichment disabled; deterministic verdict; 0 LLM generation calls; no real generation provider used.
- CORE runtime 247.286 s; capability runtime 2.689 s; measured total 249.975 s.
- All-attempt graph latency mean 68.539 ms, p50 56.570 ms, p95 147.124 ms. File I/O excluded.
- FP/FN sample counts 0/0. Parser and positive-abstention samples are saved separately and are not mislabeled as FN.
- Capability tests 5/0; IOC 3/0; RAG 3/0; full regression 174/0; compile PASS; Ruff PASS.
- Data/manifests/IOC/RAG unchanged; eight manifest checksums verified after regression; production code unchanged.
- TEST executed 0; no TEST output generated. No tuning, commit, or push.

Ready for DEV error analysis: YES. Ready for quality tuning: NO. Ready for TEST: NO.

Artifacts: dev_baseline.json, dev_baseline_preflight.json, dev_baseline_error_analysis.json, dev_baseline_runtime.log.
Measurement driver: dev_baseline_driver.py (uses existing evaluate_case/metrics and configured production graph; empty capability lists bridged to a core grouping only in memory).
