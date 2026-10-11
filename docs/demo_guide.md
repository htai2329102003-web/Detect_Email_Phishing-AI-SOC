# Local demo guide

Use only the small local fixtures in `tests/fixtures/emails/`. Do not use DEV/TEST holdout records. Docker setup and admin bootstrap details are in the [runbook](runbook.md).

1. Configure private local values in `.env`, then start the stack: `docker compose up -d --build`.
2. Check liveness: `Invoke-RestMethod http://localhost:8000/healthz`.
3. Check dependencies/readiness: `Invoke-RestMethod http://localhost:8000/readyz`.
4. Open <http://localhost:3000/login> or API docs at <http://localhost:8000/docs>; sign in as a locally provisioned Analyst.
5. Upload `tests/fixtures/emails/clean.eml` as the neutral example. The recorded G9 smoke returned score 0 with `NEEDS_ANALYST_REVIEW` because trusted-auth coverage was incomplete; this is expected conservative behavior.
6. Upload `tests/fixtures/emails/href_mismatch.eml` as the phishing-like example. The recorded G9 smoke returned score 60 and `SUSPICIOUS`.
7. Open the case and show the Evidence list, including evidence IDs, signal types, results, and provenance.
8. Show the Risk Engine `score`, `label_candidate`, contributions, coverage, and `analysis_scope`; explain that a verdict cannot change the score or candidate label.
9. Show claims with their `evidence_ids`, Gate 2 status, analyst summary, and recommended actions. Claims are checked against Gate 1 evidence.
10. Explain that new cases are `PENDING`; an Analyst can review them, and the human assessment is stored separately from the AI result. Proposed actions need explicit authorization and do not execute a real quarantine or block.

The scores above are the values in the recorded G9 HTTP smoke, not promises that every environment will return identical output. The demo needs the local PostgreSQL/IOC prerequisites in the runbook and makes no need for real LLM, RAG, VirusTotal, or urlscan calls.
