# Delivery checklist

Evidence status below reflects the checked-in source tree and the existing final DEV, TEST, and G9 artifacts. It does not trigger a new evaluation or external provider call.

- [x] `.env` is ignored and is not tracked by Git.
- [x] No secret values appear in the delivery documentation; environment examples contain empty secret fields.
- [x] Docker stack start was recorded as PASS in the G9 finalization report.
- [x] Health check was recorded as PASS in the G9 finalization report.
- [x] Readiness check was recorded as PASS in the G9 finalization report.
- [x] README complete.
- [x] Final report complete.
- [x] Demo guide complete.
- [x] DEV artifact present: `eval/results/final_dev_validation.json` and `.md`.
- [x] TEST artifact present: `eval/results/final_test_evaluation.json` and `.md`.
- [x] G9 report present: `eval/results/g9_finalization.md`.
- [x] Dataset integrity/no modification recorded in final evaluation artifacts; delivery documentation does not modify data.
- [x] Frozen R2-F configuration documented and matches final artifacts.
- [x] Known limitations documented, including recall, abstention, provider verification, and dataset coverage limits.

Verification source: [final DEV validation](../eval/results/final_dev_validation.md), [final TEST evaluation](../eval/results/final_test_evaluation.md), and [G9 finalization](../eval/results/g9_finalization.md).
