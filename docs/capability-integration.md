# Capability adapters — data v1.1.1

`eval.capability` loads the actual frozen manifests independently from `EvalCase`.
The aggregate PhishVN entry expands into individual URL records; BEC entries select
one-based CSV rows and retain both the Human class and original manifest label.
QR, security, header and attachment entries retain IDs, source, metadata, split,
expected signals and relative paths. TEST metadata is read for inventory only.
No TEST case is executed by the bounded smoke selector.

Run from the repository root:

```powershell
.venv/Scripts/python.exe -m eval.run_capabilities --root data
# Optional: explicitly call the configured structured LLM for two BEC samples.
.venv/Scripts/python.exe -m eval.run_capabilities --root data --bec-llm
```

The runner selects at most nine samples. It does not offer full DEV/TEST execution.
Reports default to `eval/results/capability-smoke.json`; writes into frozen data,
production source, configuration and tests are rejected. Exit 1 means blocked or
unavailable samples, not a failed classification prediction. Exit 2 is a runner
input/output error. Source errors are sanitized; secrets are never printed.

## Boundaries and metrics

- URL invokes the existing local URL analyzer and injected exact-match IOC client.
  QR decodes bounded image bytes through the existing QR analyzer, then uses its
  local URL/IOC path. Neither adapter navigates a URL. Classification means any
  Gate 1 validated FAIL signal; a negative requires all applicable checks complete.
  This detector policy is separate from the email Risk Engine and does not assert
  that an undetected URL is safe. It is deliberately not tuned to dataset labels.
- BEC invokes the existing content analyzer with a separately redacted copy.
  Structured LLM input has fixed system instructions and untrusted user data;
  there are no tools, score fields or verdict fields. The optional configured model
  uses the existing LLM configuration and bounded timeout without retries.
  Without explicit provider opt-in the result is UNAVAILABLE, never negative.
  Tests inject the existing deterministic fake model, independent of credentials.
- Header preserves the configured trusted-authserv policy; sender-supplied or
  untrusted authentication results remain UNKNOWN. Attachment uses only the existing
  bounded static analyzer. Neither source classification label becomes a header or
  attachment detection oracle.
- Security runs the email graph through Gate 1, Risk Engine, verdict and Gate 2,
  then reuses `evaluate_attack` and `attack_success_rate`. It checks analyzer runs
  and agreement with deterministic score/label rules. The canonical security corpus
  has no paired baseline or secret-canary oracle: those fields remain null. An
  explicit `security_spec` can supply a paired baseline/payload and synthetic secret
  canaries. No secret environment value is used as an oracle. Incomplete coverage
  makes ASR inconclusive unless an actual violation is observed. Regex detection
  alone is not attack success or a guardrail pass.

Metrics are grouped by capability, with TP/TN/FP/FN, raw ratio denominators,
unknown/unavailable/error exclusions and latency mean/p50/p95. Source SAFE is
the negative URL/QR class; BEC uses positive/neutral. MIXED remains language or
aggregate metadata. SPAM and PROMPT_INJECTION are never coerced to phishing.
Empty expected-signals lists are excluded from evidence recall; unavailable
metrics are null. CORE F1 is neither run nor merged with capability metrics.

## Verified package and blockers

- URL: 53,116; source PHISHING 36,706 / SAFE 16,410; vi 46,827 / mixed 6,289.
- BEC: 279; positive 276 / neutral 3; synthetic and human validated, not real-world.
- QR: manifest 1,000 (500 SAFE / 500 PHISHING), **1,000 broken paths**.
  Physical folders contain 1,500 PNGs (500 benign / 1,000 phishing), under different
  names. Example manifest `capability/qr/benign/qr_0_benign_images.png` is absent;
  actual filenames include `qr_benign_0110a648.png`. No inferred relinking is used.
  Canonical QR execution is blocked before decoding; deterministic temporary-image
  adapter tests pass. Frozen data is untouched.
- Security: 3,149, all paths present. The real smoke has no rule violations, but
  incomplete auth coverage makes ASR null (0/0), not a claimed 0% success rate.
- Auth: 180 metadata-selected cases: DEV 121 / TEST 59, all paths present; PARTIAL/MVP.
- Attachment: 983 manifest references: CORE 260, security 708, auxiliary 15.
  CORE/security 968 exist; all 15 auxiliary files are absent. There is no separate
  attachment oracle corpus and no invented expected signal. Smoke uses one existing
  security attachment; auxiliary and TEST are not executed.

The real nine-slot smoke includes two QR blocked results. URL phishing was missed
(FN), benign was negative (TN). Configured BEC returned TP for positive and FP for
neutral. These are retained observations, not grounds to alter risk weights or
source labels. Adapter execution PASS is distinct from prediction correctness.
The report is a small smoke artifact, not production metrics or a benchmark.

IOC exact matching and the real Qdrant repository are verified read-only without
index rebuild, embedding calls or upserts. Full regression: 174 tests passed,
including 5 minimal adapter tests. Dataset inventory remains unchanged.
