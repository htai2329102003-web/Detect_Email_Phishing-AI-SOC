# P0 remediation result

P0 coverage fix COMPLETE. Parser P0 fix COMPLETE. Valid DEV quality baseline AVAILABLE.
Ready for DEV quality tuning: YES. Ready for TEST: NO. No tuning was performed.

## Coverage contract

- UNKNOWN authentication remains UNKNOWN; missing authentication adds no risk.
- SAFE still requires complete coverage. Weak incomplete cases remain REVIEW.
- Incomplete coverage can preserve PHISHING only when independent non-LLM evidence reaches the existing phishing threshold using existing family caps, weights and overrides.
- Rejected/unconfigured/contradictory evidence still blocks the incomplete-coverage exception.
- IOC is not hardcoded to PHISHING; the existing score/override contract applies.
- All 3,308 previously successful cases retain exactly the same risk scores. No new execution failures among them.

## Parser

Previous failures: 150. Recovered: 148 (145 partial-recoverable + 3 robustness cases).
Remaining failures: 2 genuine malformed-MIME rejections, `e2a_04809eff` and `e2a_77e5a36b`.
All 3 identified malformed Message-ID robustness cases recover.

Original bytes and ordered raw header occurrences remain available to analyzers. Unreliable identity fields are unavailable; duplicates are not resolved by choosing a value. Partial parses emit UNKNOWN HEADER_ANALYSIS evidence with warnings and retain incomplete coverage. Bounded body-only and damaged-transfer-encoding recovery is explicitly partial. Ambiguous MIME Content-Type and missing multipart boundaries remain rejected; size/part/depth limits remain enforced.

The small malformed test fixture now represents a genuinely broken multipart boundary; headerless text is covered separately as a partial parse. No files under `data/` were modified.

## Deterministic DEV smoke

| Group | Cases | PHISHING | REVIEW | Execution errors |
|---|---:|---:|---:|---:|
| SAFE ground truth | 5 | 0 | 5 | 0 |
| Ordinary PHISHING | 5 | 0 | 5 | 0 |
| Malicious-IOC PHISHING | 5 | 5 | 0 | 0 |
| Previously parser-rejected | 5 | 1 | 4 | 0 |

PASS: 6/20 non-REVIEW decisions, no unsafe SAFE decisions, no crashes.
Smoke passed before full DEV and was rechecked after lint-only runner cleanup.

## Full DEV

Canonical: 3,462. Defender quarantine skipped without reading: 4. Attempted: 3,458.
Successful: 3,456. Execution errors: 2 (controlled MIME rejection).

| Ground truth | SAFE | SUSPICIOUS | PHISHING | REVIEW | Error |
|---|---:|---:|---:|---:|---:|
| SAFE | 0 | 0 | 24 | 2,726 | 0 |
| PHISHING | 0 | 0 | 103 | 603 | 2 |
| Total | 0 | 0 | 127 | 3,329 | 2 |

The existing selective binary metric policy excludes abstentions and execution errors: PHISHING is positive; SAFE/SUSPICIOUS are negative. REVIEW remains a separate label.

| Metric | Numerator / denominator | Value |
|---|---|---:|
| TP / TN / FP / FN | 103 / 0 / 24 / 0 | |
| Precision | 103 / 127 | 81.1024% |
| Recall (selective) | 103 / 103 | 100% |
| F1 (selective) | 206 / 230 | 89.5652% |
| Accuracy (selective) | 103 / 127 | 81.1024% |
| FPR (selective) | 24 / 24 | 100% |
| FNR (selective) | 0 / 103 | 0% |
| Recall including positive abstentions and errors | 103 / 708 | 14.5480% |
| Decision coverage over successful predictions | 127 / 3,456 | 3.6748% |
| Abstention over successful predictions | 3,329 / 3,456 | 96.3252% |

Selective recall/F1 are not end-to-end performance estimates. Most cases still abstain; no negative decisions occurred. This DEV validation is not a production benchmark.

## Malicious IOC

Original 47 malicious-IOC cases: PHISHING 47, SUSPICIOUS 0, REVIEW 0; solely coverage-blocked 0.
Including recovered parser cases: 59 malicious-IOC cases, all PHISHING.

## Regression and safety

- Parser-focused: 11 PASS / 0 FAIL (10 unrelated tests deselected).
- Core-contract/Risk Engine: 23 PASS / 0 FAIL.
- Capability + IOC + RAG: 11 PASS / 0 FAIL.
- Full regression: 185 PASS / 0 FAIL.
- `python -m compileall src`: PASS.
- `ruff check src tests`: PASS. Additional runner lint: PASS.
- Full DEV and final smoke: PASS.
- Data modified: NO. Manifest checksums: 8 checked, 0 mismatches.
- TEST cases executed: 0. Real external API/LLM calls: 0.
- Weights/thresholds, authserv whitelist, IOC/RAG semantics: unchanged.
- Production/config hashes still match the full DEV execution after runner import/comment cleanup.
- Commit/push: NO.

## Files in this task

Modified: `src/evidence/risk_engine.py`, `src/parsers/email_parser.py`, `src/agents/nodes/header_node.py`, `src/analyzers/header_analyzer.py`, `tests/test_core_contracts.py`, `tests/test_vertical_slice.py`, `tests/test_external_boundaries.py`, `tests/fixtures/emails/malformed.eml`.

Created: `tests/test_p0_remediation.py`, `eval/results/p0_remediation_driver.py`, `eval/results/p0_parser_recovery.json`, `eval/results/p0_smoke.json`, `eval/results/p0_dev_baseline.json`, this report.

Deleted: none. Pre-existing workspace changes and previous baseline artifacts were preserved.

## Commands and artifacts

Run from the project root using the project virtual environment:

```powershell
python -B eval/results/p0_remediation_driver.py smoke
python -B eval/results/p0_remediation_driver.py full
```

Full execution requires a passing smoke for the current code and DEV manifest. External enrichment and RAG must be disabled; no manifest overrides/fake IOC records are accepted. The four known quarantined DEV cases are never opened.

`p0_dev_baseline.json` retains predictions, safe evidence, coverage/reasons, selective counts, provider usage, data immutability checks and hashes from the actual full execution. Two parser failures count as unexpected relative to the unchanged manifest (which has no expected-error oracle), but are the two deliberately retained rejections in P0 acceptance.

Remaining quality limitations: 96.3252% abstention, unavailable authentication/other coverage, and 24 SAFE-ground-truth positive decisions requiring provenance/temporal/label-alignment analysis. No further remediation or Stage-7 work was started.
