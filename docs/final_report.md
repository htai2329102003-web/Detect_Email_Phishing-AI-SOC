# PhishHunter final delivery report

## System

PhishHunter is a local-first email triage system with a FastAPI API, a LangGraph analysis workflow, PostgreSQL case persistence, and a Next.js analyst interface. The Docker Compose stack contains backend, frontend, PostgreSQL, and Qdrant. Static analysis works on `.eml` input and does not fetch embedded URLs or execute attachments.

The main decision flow is:

```text
Email → Parser and analyzers → Evidence → Gate 1 → Risk Engine
      → Verdict → Gate 2 / Claim Validator → PENDING case → HITL review
```

The Header, URL, Attachment, and QR analyzers produce structured evidence with signal type, family, provenance, and confidence. Gate 1 validates evidence before scoring. The deterministic Risk Engine owns `score` and `label_candidate`; the Verdict layer supplies evidence-linked claims, recommended actions, and an analyst summary. Gate 2 checks claims against evidence already accepted by Gate 1. Failed or incomplete trust/coverage conditions can require analyst review. HITL decisions, analyst assessments, and audit events are stored separately from the immutable AI assessment. Proposed actions require authorization and do not execute destructive operations.

## Deterministic policy and integration boundaries

The frozen R2-F configuration is:

| Setting | Value |
| --- | ---: |
| PHISHING threshold | 62 |
| SUSPICIOUS threshold | 30 |
| `URL_IP_LITERAL` | 0.55 |
| `IOC_DERIVED_DOMAIN` | 0.20 |

The partial-header SUSPICIOUS exception is bounded by sufficiently strong local URL/attachment evidence, completed analyzer markers, auth/identity-only remaining coverage gaps, successful tools, and no evidence-integrity errors. Incomplete coverage remains visible; missing signal or unavailable results are not synthesized as clean. `NEEDS_ANALYST_REVIEW` remains a separate outcome.

IOC lookup uses normalized local exact-match data. RAG is an optional knowledge-context source and does not change deterministic score. Content/BEC and verdict LLM are opt-in boundaries; their real providers were not called for final evaluation. VirusTotal is limited to hash lookup and urlscan to lookup/result retrieval; no upload, URL submission, or real provider request was made. Langfuse remote export was not exercised; its metadata-only exporter was mock-tested. Optional integrations are not implied to be operational by the presence of configuration fields.

Security controls include keeping email text as untrusted input, analyzing raw content locally while only sending redacted copies to optional LLM boundaries, evidence-grounded claims, role-based API access, private environment secrets, and structured logs that omit raw email and secrets. Optional provider failures fail closed; the system does not turn an external error into a SAFE result. No automated quarantine, block, or deletion occurs.

## Dataset

Dataset version `1.1.1` is frozen for this evaluation. The canonical core contains 3,491 SAFE messages and 1,199 phishing messages (999 real and 200 synthetic), 4,690 total. DEV has 3,462 records; TEST has 1,028. Capability collections contain 53,116 Vietnamese URL records, 279 BEC records, 1,000 QR records, 3,149 prompt-injection records, 180 Auth Header records, 983 attachment references, 1,105,349 IOC records, and 788 RAG documents split into 1,161 chunks.

These counts describe different units and overlapping capability collections; they must not be added together as one homogeneous email corpus. In particular, the capability counts do not imply a corresponding count of labeled email messages.

## DEV selection and final results

Risk policy selection/tuning used DEV only. R2-F was frozen before the final TEST evaluation. TEST was not used to tune thresholds, weights, or policy. The final DEV artifact records dataset v1.1.1, eight manifest checksums verified with zero mismatches, unchanged DEV split hash, and one deterministic final replay. The final TEST artifact records a first inference pass that completed 1,024 analyses but could not be scored because the runner failed to retain prediction records. A recovery-only runner fix was checked with synthetic aggregation data, then one TEST pass was rerun to capture metrics. No initial TEST metrics were observed, and neither pass was used for tuning.

| Metric | DEV | TEST |
| --- | ---: | ---: |
| Phishing recall | 26.1299% (185/708) | 25.0883% (71/283) |
| Precision | 96.3542% (185/192) | 100.0000% (71/71) |
| SAFE FPR | 0.2545% (7/2,750) | 0.0000% (0/741) |
| Decision coverage | 24.7396% (855/3,456) | 23.4375% (240/1,024) |
| Abstention / review | 75.2604% (2,601/3,456) | 76.5625% (784/1,024) |

| Confusion count | DEV | TEST |
| --- | ---: | ---: |
| TP | 185 | 71 |
| TN | 481 | 88 |
| FP | 7 | 0 |
| FN | 182 | 81 |

Review/abstention is retained as its own label and is included in the denominators shown in the source artifacts. Precision describes only the messages predicted as PHISHING. It is not an end-to-end accuracy measure; recall, decision coverage, and abstention must be read together. These are curated-split evaluation metrics, not production metrics.

The final replay skipped four Defender-quarantined E2A files from each split. DEV attempted 3,458 records, with 3,456 successful analyses and two execution errors; TEST attempted and successfully analyzed 1,024 records with zero execution errors. No real LLM, RAG/embedding, VirusTotal, urlscan, or Langfuse calls were made for those final evaluations.

## Verified limits

- Final TEST phishing recall is about 25.1%, while abstention is 76.6%; most outcomes still require analyst review.
- Many emails do not include trusted Authentication-Results coverage. SAFE remains intentionally conservative and was not reached by any record in either final split.
- Some phishing messages have no positive deterministic signal in the current analyzers.
- Weak BEC evidence currently has no classification impact under the frozen Risk Engine policy. BEC samples are synthetic and human-validated, not a real-world email corpus.
- There is no Vietnamese email corpus and no email-with-QR corpus. Vietnamese URL and QR capability data exist as separate datasets.
- Auth Header capability is partial.
- Eight E2A samples were unavailable on Windows after Defender quarantine (four DEV and four TEST); those files were skipped without opening them.
- Real VirusTotal and urlscan provider behavior was not verified because keys were not configured. Real LLM, RAG retrieval, embedding, and Langfuse remote export were not exercised in final validation.
- The final TEST first pass was unscorable due to a runner aggregation bug; its prediction records were not recoverable. The reported final TEST numbers are from the single recovery pass, with R2-F unchanged.

## G9 deployment and observability

The G9 finalization artifact reports Docker deployment, health, readiness, structured logging, environment validation, optional-provider fail-closed behavior, and the final local smoke as PASS. It records 25 targeted tests passing, with changed-file compile and Ruff checks passing. The HTTP smoke uploaded `href_mismatch.eml` and a neutral `clean.eml` with an in-memory privacy canary; both returned HTTP 200, passed Gate 2, persisted as PENDING PostgreSQL cases, and were read back. Their scores/labels were respectively 60/SUSPICIOUS and 0/NEEDS_ANALYST_REVIEW. The runtime smoke did not exercise real external providers. Langfuse remote export was not live-tested, and process-local metrics reset on restart. See [G9 finalization record](../eval/results/g9_finalization.md) for evidence and scope.

## Source artifacts

- [Final DEV validation JSON](../eval/results/final_dev_validation.json) and [Markdown](../eval/results/final_dev_validation.md)
- [Final TEST evaluation JSON](../eval/results/final_test_evaluation.json) and [Markdown](../eval/results/final_test_evaluation.md)
- [G9 finalization report](../eval/results/g9_finalization.md)
