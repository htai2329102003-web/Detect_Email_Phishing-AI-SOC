# DEV quality tuning ? Round 1

Dataset 1.1.1. DEV only. P0 artifacts preserved. No production benchmark claim.

## Result

Selected C4. Canonical 3,462; Defender quarantine skipped 4 (never opened); attempted 3,458; successful 3,456; controlled MIME errors 2. Full graph predictions exactly match frozen-evidence candidate replay.

Production changes: URL-derived domain relations use IOC_DERIVED_DOMAIN, weight 0.20 and no override; phishing threshold 70 ? 65; opt-in partial SUSPICIOUS decisions. Suspicious threshold 30, all family caps, required authentication signals and SAFE complete-coverage requirement remain unchanged.

Partial SUSPICIOUS requires deterministic strength at least 30, no Gate-1 rejection/unconfigured/contradictory evidence, no partial parser marker, no failed tool and no missing checks outside identity/auth. Strong deterministic PHISHING remains actionable despite unrelated UNKNOWN checks. UNKNOWN is never PASS. LLM strength cannot unlock partial positive conclusions.

## P0 and Round-1 metrics

The existing binary projection treats SAFE/SUSPICIOUS as negative and REVIEW as abstention. TN/FN below include SUSPICIOUS and do not imply SAFE decisions. Whole-DEV recall keeps all 708 executable phishing cases, including abstentions and the two MIME failures. Whole-DEV SAFE FPR keeps all 2,750 executable SAFE cases.

| Metric | P0 | C4 full graph |
|---|---:|---:|
| SAFE | 0 | 0 |
| SUSPICIOUS | 0 | 661 |
| PHISHING | 127 | 149 |
| NEEDS_ANALYST_REVIEW | 3329 | 2646 |
| TP | 103 | 142 |
| TN | 0 | 478 |
| FP | 24 | 7 |
| FN | 0 | 183 |
| Whole DEV: phishing_recall | 14.5480% (103/708) | 20.0565% (142/708) |
| Whole DEV: safe_fpr | 0.8727% (24/2750) | 0.2545% (7/2750) |
| Whole DEV: precision | 81.1024% (103/127) | 95.3020% (142/149) |
| Whole DEV: decision_coverage | 3.6748% (127/3456) | 23.4375% (810/3456) |
| Whole DEV: abstention | 96.3252% (3329/3456) | 76.5625% (2646/3456) |
| Whole DEV: suspicious_rate | 0.0000% (0/3456) | 19.1262% (661/3456) |
| Whole DEV: execution_error_rate | 0.0578% (2/3458) | 0.0578% (2/3458) |
| Whole DEV: safe_precision | N/A | N/A |
| SELECTIVE: precision | 81.1024% (103/127) | 95.3020% (142/149) |
| SELECTIVE: recall | 100.0000% (103/103) | 43.6923% (142/325) |
| SELECTIVE: f1 | 89.5652% (206/230) | 59.9156% (284/474) |
| SELECTIVE: accuracy | 81.1024% (103/127) | 76.5432% (620/810) |
| SELECTIVE: fpr | 100.0000% (24/24) | 1.4433% (7/485) |

SAFE precision remains unavailable, not zero: there are no SAFE decisions. Review drops 3,329 ? 2,646, but 76.5625% still abstain. Of 661 SUSPICIOUS cases, 478 are SAFE ground truth and 183 PHISHING ground truth. Triage (PHISHING or SUSPICIOUS) phishing recall is 325/708 = 45.9040%; SAFE escalation is 485/2,750 = 17.6364%. This analyst workload is a remaining limitation.

## False-positive audit before tuning

All 24 FP cases were examined before production edits. 22 are driven by URL-derived domain scope overreach, not direct matches to the source malicious URL. Domains include shared URL-shortening, search and advertising hosts. The other 2 combine HREF_MISMATCH (.60) with identity (.25), producing score 70 under noisy-OR. No correlation caps were changed.

IOC_MATCH is the dominant contribution in 22 FP cases; HREF_MISMATCH dominates the other 2. Exact host lookup is valid, but inheriting whole-domain malice from a URL path is too strong. Source confidence was not silently changed; a separate weaker relation signal preserves the fact and provenance. Direct malicious URL/IP/hash and explicit non-derived domain assertions retain the original .95 weight / override.

All 22 IOC-driven FPs have source-observation years later than email Date (2002 versus 2022?2024). Date is untrusted; no effective interval or reliable expiry metadata is available. Primary classification: DERIVED_SIGNAL_TOO_STRONG 22. Secondary temporal-observation mismatch 22; merged malicious/reference provenance 5. PROVENANCE_WEAK proven: 0. Current live maliciousness and historical effective validity: UNKNOWN, not verified using API. No temporal filtering or domain allowlisting was introduced.

Canonical rows can merge Tranco ranks with feed observations. Tranco ranks are reference observations; the malicious-source counts are PhishTank 22 and OpenPhish 5 (overlap), not Tranco.

| Sample ID | Source dataset | Score | Root cause |
|---|---|---:|---|
| sa_easy_f9a32dff | sa_easy | 98.05 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_easy_91ae5157 | sa_easy | 96.25 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_easy_50ad5d16 | sa_easy | 96.75 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_easy_a530d655 | sa_easy | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_bba5a387 | sa_hard | 70.0 | URL_IDENTITY_HEURISTIC_COMBINATION |
| sa_hard_ce00a8e7 | sa_hard | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_de669114 | sa_hard | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_01b9c668 | sa_hard | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_51aeb44a | sa_hard | 96.25 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_63e19b00 | sa_hard | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_f58b422b | sa_hard | 96.75 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_bb6d8d31 | sa_hard | 96.25 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_c1b59d23 | sa_hard | 96.25 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_5659d866 | sa_hard | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_d547f403 | sa_hard | 98.05 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_57a72387 | sa_hard | 98.05 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_28d755b5 | sa_hard | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_8eb0088e | sa_hard | 70.0 | URL_IDENTITY_HEURISTIC_COMBINATION |
| sa_hard_37b57de1 | sa_hard | 98.05 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| sa_hard_3d6e308b | sa_hard | 98.05 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| e2a_2d0ebc8d | e2a_bench | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| e2a_17f24a44 | e2a_bench | 95.0 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| e2a_6c7fe49f | e2a_bench | 96.75 | DERIVED_DOMAIN_SCOPE_OVERREACH |
| e2a_1833b220 | e2a_bench | 96.75 | DERIVED_DOMAIN_SCOPE_OVERREACH |

Every FP includes evidence IDs, signal types, families, analyzer/tool provenance, individual contributions, IOC role/type/derived relation, source records, source timestamps, effective-interval availability and email Date in dev_tuning_round1_audit.json. No raw email bodies are saved. The separate first FP audit records the original 24-case observations.

## Abstention audit before tuning

SAFE reviews 2,726; PHISHING reviews 603. Main categories are exclusive and sum to these totals; overlapping facts are separately recorded.

| Main blocking category | SAFE | PHISHING |
|---|---:|---:|
| AUTH_UNKNOWN | 1614 | 451 |
| INSUFFICIENT_COVERAGE_FOR_SAFE | 894 | 23 |
| PARTIAL_PARSE | 36 | 94 |
| SCORE_BELOW_PHISHING | 182 | 34 |
| TOOL_UNKNOWN | 0 | 1 |

All review cases have UNKNOWN auth. No positive-risk signals: SAFE 1,258, PHISHING 171. Meaningful risk blocked by partial-decision contract: SAFE 529, PHISHING 310 (overlapping categories). Partial parse: SAFE 36, PHISHING 94. Auth-only coverage gap: SAFE 1,614, PHISHING 451.

PHISHING review score: p25 0, p50 35, p75 60, p90 66.4, p95 66.4, max 66.4. Near suspicious threshold (25?35): 126. Near phishing threshold (65?75): 70. Signal-less: 171. Disabled content/BEC could be relevant to missed cases but neither a benefit nor a count requiring that capability can be established without additional oracles.

| Review coverage bucket | SAFE | PHISHING |
|---|---:|---:|
| below_0.25 | 0 | 0 |
| 0.25_to_0.50 | 2 | 48 |
| 0.50_to_0.75 | 2652 | 291 |
| at_least_0.75 | 72 | 264 |

Bucket-level score distributions and known/UNKNOWN families, plus per-label strongest signals, positive-family counts, IOC status and signal counts for URL/header/attachment/QR/content are in the audit JSON. Completion markers are not proof that an actual payload was inspected. No coverage bucket supports SAFE under the unchanged policy: every successful case lacks trusted complete authentication. No SAFE coverage threshold was relaxed or fitted.

## Effective policy

P0 thresholds: suspicious 30, phishing 70. Selected thresholds: suspicious 30, phishing 65. Required signals: SPF_FAIL, DKIM_FAIL, DMARC_FAIL. SAFE requires coverage.complete (all expected checks known and no rejection/configuration/conflict reason), not a lowered numeric ratio. Auth trust remains fail-closed and empty.

Family caps: email_auth .45, identity .45, url_deception .60, attachment .50, qr .00, threat_intel .95, content_bec .15. IOC_MATCH override minimum score 95 at confidence ? .90, excluding LLM. IOC_DERIVED_DOMAIN has no override. Existing individual weights are frozen in the audit policy; only the new .20 relation weight is added.

SUSPICIOUS was unreachable for incomplete coverage because P0 allowed only the PHISHING exception. The new opt-in contract restores positive triage without claiming safety. SAFE remains structurally unreachable in this corpus/configuration because required trusted auth is unavailable; this was not tuned away.

## Candidate comparison

Six explainable candidates, no brute force. C0 reproduces P0 exactly. Stages: correct demonstrated scope error; test partial positive triage; test nearby phishing thresholds; test suspicious threshold separately. No SAFE relaxation or family-cap search.

| ID | Derived correction | Partial SUSPICIOUS | Phish/Susp threshold | TP/TN/FP/FN | SAFE/SUSP/PHISH/REVIEW |
|---|---|---|---|---|---|
| C0 | False | False | 70/30 | 103/0/24/0 | 0/0/127/3329 |
| C1 | True | False | 70/30 | 69/0/2/0 | 0/0/71/3385 |
| C2 | True | True | 70/30 | 69/483/2/252 | 0/735/71/2650 |
| C3 | True | True | 75/30 | 9/484/0/301 | 0/785/9/2662 |
| C4 | True | True | 65/30 | 142/478/7/183 | 0/661/149/2646 |
| C5 | True | True | 70/40 | 69/469/2/213 | 0/682/71/2703 |

| ID | Whole DEV recall | SAFE FPR | Precision | Decision coverage | Abstention |
|---|---:|---:|---:|---:|---:|
| C0 | 14.5480% (103/708) | 0.8727% (24/2750) | 81.1024% (103/127) | 3.6748% (127/3456) | 96.3252% (3329/3456) |
| C1 | 9.7458% (69/708) | 0.0727% (2/2750) | 97.1831% (69/71) | 2.0544% (71/3456) | 97.9456% (3385/3456) |
| C2 | 9.7458% (69/708) | 0.0727% (2/2750) | 97.1831% (69/71) | 23.3218% (806/3456) | 76.6782% (2650/3456) |
| C3 | 1.2712% (9/708) | 0.0000% (0/2750) | 100.0000% (9/9) | 22.9745% (794/3456) | 77.0255% (2662/3456) |
| C4 | 20.0565% (142/708) | 0.2545% (7/2750) | 95.3020% (142/149) | 23.4375% (810/3456) | 76.5625% (2646/3456) |
| C5 | 9.7458% (69/708) | 0.0727% (2/2750) | 97.1831% (69/71) | 21.7882% (753/3456) | 78.2118% (2703/3456) |

C4 is selected: compared with P0 it improves whole-DEV recall, precision, FPR, coverage and abstention without unsafe SAFE or additional execution failures. Versus C2, it trades 5 additional FP for 73 additional TP. C3 reduces FP to zero but loses most detection. C5 does not recover recall. No claim of final optimality.

What worsened: selective F1 falls because meaningful SUSPICIOUS cases now enter the negative projection, while P0 excluded them as abstentions. Real triage workload remains high. Correcting overreach also removes unsupported strong decisions: the former 59 IOC-hit cases become 11 PHISHING, 19 SUSPICIOUS, 29 REVIEW. Normal risk aggregation still applies; direct malicious assertions retain their contract. Of the original 24 FP, 7 remain PHISHING, 6 become SUSPICIOUS, 11 REVIEW.

## Validation and artifacts

Full graph matches C4 replay for every attempted DEV case. Gate 2: 3,456 PASS. Regression: 198 PASS / 0 FAIL (previous 185, plus 13 Round-1 cases). Focused Risk/Parser/IOC/Round-1: 60 PASS. Capability/IOC/RAG: 11 PASS. Compile and Ruff: PASS. No new production changes after full validation.

Error samples are metadata-only in dev_tuning_round1.json: 7 remaining FP, 10 PHISHING abstentions and 10 selective FN (SUSPICIOUS, not SAFE). Full contributions and high-level causes are included.

Files modified this round: config/risk_weights.yaml; src/analyzers/common.py; src/evidence/risk_engine.py; tests/test_core_contracts.py; tests/test_p0_remediation.py; tests/test_ioc_index.py; docs/ioc-integration.md. P0 regression tests explicitly freeze the P0 policy; new tests cover the selected opt-in policy and direct/derived IOC scope.

Created: eval/round1.py; tests/test_round1_tuning.py; eval/results/dev_tuning_round1_fp_audit.json; dev_tuning_round1_evidence.jsonl; dev_tuning_round1_audit.json; dev_tuning_round1_candidates.json; dev_tuning_round1_selection.json; dev_tuning_round1.json; this report. Deleted: none. Pre-existing workspace changes were preserved.

Commands (project virtual environment):

    python -B -m eval.round1 audit
    python -B -m eval.round1 enrich-audit
    python -B -m eval.round1 candidates
    python -B -m eval.round1 validate

Audit required frozen P0 production code and refuses to truncate the evidence cache after tuning. Candidates can be replayed from the frozen cache. Validation asserts selected C4 policy and exact parity with its predictions. No TEST paths are loaded.

## Safety and final status

Data modified: NO. Eight manifest checksum entries verified, zero mismatches. P0 artifacts unchanged. TEST holdout executions/predictions/metrics/error analysis: 0. No labels or splits changed. UNKNOWN ? PASS: NO. Authserv whitelist changes: NO. Sample-specific production rules: NO. New VirusTotal/urlscan: NO. Real API/LLM calls: 0. Commit/push: NO.

Content/BEC DISABLED; real LLM verdict DISABLED (deterministic reporter active); RAG DISABLED. Stage-7 completeness blocker: YES. Content/BEC impact is unmeasured; enabling a verdict model or contextual RAG cannot directly fix deterministic risk recall. No external feature was enabled.

ROUND-1 TUNING COMPLETE: YES. DEV QUALITY IMPROVED: YES. READY FOR ROUND-2 TUNING: YES. READY FOR FINAL TEST: NO.

Remaining quality blockers: 76.5625% abstention, phishing detection recall only 20.0565%, 7 remaining FP, 478 SAFE-ground-truth SUSPICIOUS decisions, 381 phishing reviews and 183 phishing SUSPICIOUS decisions, unavailable trusted auth preventing SAFE, temporal/provenance alignment limits, and missing content/BEC capability. Two genuine MIME rejections remain deliberate. Stop; no further tuning or Stage-7 implementation in this round.
