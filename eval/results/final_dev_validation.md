# Final DEV validation

**Status: PASS.** One deterministic replay of the selected R2-F policy matched Round 2 exactly. This is a DEV validation, not a TEST or production benchmark.

## Effective configuration

- PHISHING threshold: 62
- SUSPICIOUS threshold: 30
- `URL_IP_LITERAL`: 0.55
- `IOC_DERIVED_DOMAIN`: 0.20
- Partial-header SUSPICIOUS remains bounded by local URL/attachment evidence of strength at least 0.35, a completed analyzer marker, auth/identity-only remaining gaps, successful tools, and no integrity errors.
- No risk or policy environment overrides were active.

## Data integrity

- Dataset version: 1.1.1
- Manifest checksums: 8 verified, 0 mismatches
- DEV manifest SHA-256 matches Round-2 baseline: yes
- DEV split: 3462 canonical (2750 SAFE, 712 PHISHING); changed: no
- TEST executed: 0; no TEST predictions were read
- Data modified: no

## Final DEV replay

| Measure | Result |
|---|---:|
| Canonical | 3462 |
| Defender skipped | 4 |
| Attempted / successful / execution errors | 3458 / 3456 / 2 |
| SAFE / SUSPICIOUS / PHISHING / REVIEW | 0 / 663 / 192 / 2601 |
| TP / TN / FP / FN | 185 / 481 / 7 / 182 |
| Phishing recall | 26.1299% |
| SAFE FPR | 0.2545% |
| Precision | 96.3542% |
| Decision coverage | 24.7396% |
| Abstention | 75.2604% |

Label counts, confusion counts, and displayed metrics match Round 2. Percentages are compared to four decimal places.

## Validation and cost

- Focused Risk Engine, partial-header, and policy tests: 45 passed, 0 failed
- Compile: PASS (`src/evidence/risk_engine.py`)
- Ruff: PASS (`src/evidence/risk_engine.py`)
- LLM / RAG / VirusTotal / urlscan calls: 0 / 0 / 0 / 0
- Production code/config and data were not changed during this validation.

**R2-F frozen: YES**  
**Final DEV validation: PASS**  
**Ready for final TEST: YES**
