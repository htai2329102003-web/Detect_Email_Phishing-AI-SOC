# DEV quality tuning Round 2

DEV only; cached deterministic evidence; not a production benchmark.

## Candidate search

| Candidate | Changes | TP | TN | FP | FN | SAFE | SUSPICIOUS | PHISHING | REVIEW | Recall % | Precision % | FPR % | Coverage % | Abstention % |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| C4 baseline | {} | 142 | 478 | 7 | 183 | 0 | 661 | 149 | 2646 | 20.0565 | 95.3020 | 0.2545 | 23.4375 | 76.5625 |
| R2-A | {"phishing": 60} | 229 | 465 | 27 | 126 | 0 | 591 | 256 | 2609 | 32.3446 | 89.4531 | 0.9818 | 24.5081 | 75.4919 |
| R2-B | {"phishing": 62} | 149 | 478 | 7 | 178 | 0 | 656 | 156 | 2644 | 21.0452 | 95.5128 | 0.2545 | 23.4954 | 76.5046 |
| R2-C | {"ip_weight": 0.55} | 167 | 478 | 7 | 162 | 0 | 640 | 174 | 2642 | 23.5876 | 95.9770 | 0.2545 | 23.5532 | 76.4468 |
| R2-D | {"ip_weight": 0.55, "phishing": 62} | 185 | 478 | 7 | 150 | 0 | 628 | 192 | 2636 | 26.1299 | 96.3542 | 0.2545 | 23.7269 | 76.2731 |
| R2-E | {"bounded_partial_header": true} | 142 | 481 | 7 | 221 | 0 | 702 | 149 | 2605 | 20.0565 | 95.3020 | 0.2545 | 24.6238 | 75.3762 |
| R2-F | {"ip_weight": 0.55, "phishing": 62, "bounded_partial_header": true} | 185 | 481 | 7 | 182 | 0 | 663 | 192 | 2601 | 26.1299 | 96.3542 | 0.2545 | 24.7396 | 75.2604 |

### Label transitions by ground truth

| Candidate | Phishing REVIEW → SUSPICIOUS | Phishing REVIEW → PHISHING | Phishing SUSPICIOUS → PHISHING | SAFE newly PHISHING |
|---|---:|---:|---:|---:|
| R2-A | 0 | 30 | 57 | 20 |
| R2-B | 0 | 2 | 5 | 0 |
| R2-C | 0 | 4 | 21 | 0 |
| R2-D | 0 | 10 | 33 | 0 |
| R2-E | 38 | 0 | 0 | 0 |
| R2-F | 32 | 10 | 33 | 0 |

## Error analysis

183 phishing SUSPICIOUS; 381 phishing REVIEW; 7 FP. Missing auth affects every case in these groups.
171 phishing REVIEW cases have no positive deterministic evidence. 103 lack HEADER_ANALYSIS; 30 lack URL_ANALYSIS.
Phishing SUSPICIOUS includes 70 IP-literal detections; phishing REVIEW includes 18. Family correlation remains max-per-family.
The 7 existing FP: five score 68.8 from obfuscated URL + reply-to mismatch + derived-domain IOC; two score 70 from href mismatch + identity.
No repeated temporal IOC audit. Exact per-case contributions and candidate effects are in JSON.

## Selection and validation

```json
{
  "complete": true,
  "baseline_policy": {
    "version": 1,
    "thresholds": {
      "suspicious": 30.0,
      "phishing": 65.0
    },
    "required_signals": [
      "SPF_FAIL",
      "DKIM_FAIL",
      "DMARC_FAIL"
    ],
    "llm_weight_cap": 0.1,
    "families": {
      "email_auth": {
        "cap": 0.45
      },
      "identity": {
        "cap": 0.45
      },
      "url_deception": {
        "cap": 0.6
      },
      "attachment": {
        "cap": 0.5
      },
      "qr": {
        "cap": 0.0
      },
      "threat_intel": {
        "cap": 0.95
      },
      "content_bec": {
        "cap": 0.15
      }
    },
    "weights": {
      "SPF_FAIL": {
        "family": "email_auth",
        "weight": 0.25
      },
      "DKIM_FAIL": {
        "family": "email_auth",
        "weight": 0.35
      },
      "DMARC_FAIL": {
        "family": "email_auth",
        "weight": 0.45
      },
      "REPLY_TO_MISMATCH": {
        "family": "identity",
        "weight": 0.4
      },
      "RETURN_PATH_MISMATCH": {
        "family": "identity",
        "weight": 0.25
      },
      "DISPLAY_NAME_DOMAIN_MISMATCH": {
        "family": "identity",
        "weight": 0.25
      },
      "RECEIVED_CHAIN_ANOMALY": {
        "family": "identity",
        "weight": 0.2
      },
      "HREF_MISMATCH": {
        "family": "url_deception",
        "weight": 0.6
      },
      "URL_IP_LITERAL": {
        "family": "url_deception",
        "weight": 0.4
      },
      "URL_PUNYCODE": {
        "family": "url_deception",
        "weight": 0.2
      },
      "URL_LOOKALIKE": {
        "family": "url_deception",
        "weight": 0.5
      },
      "URL_EXCESSIVE_SUBDOMAIN": {
        "family": "url_deception",
        "weight": 0.25
      },
      "URL_SHORTENER": {
        "family": "url_deception",
        "weight": 0.2
      },
      "URL_SUSPICIOUS_PORT": {
        "family": "url_deception",
        "weight": 0.25
      },
      "URL_OBFUSCATED": {
        "family": "url_deception",
        "weight": 0.35
      },
      "HEADER_ANALYSIS": {
        "family": "identity",
        "weight": 0.0
      },
      "URL_ANALYSIS": {
        "family": "url_deception",
        "weight": 0.0
      },
      "ATTACHMENT_ANALYSIS": {
        "family": "attachment",
        "weight": 0.0
      },
      "ATTACHMENT_METADATA": {
        "family": "attachment",
        "weight": 0.0
      },
      "ATTACHMENT_EXECUTABLE": {
        "family": "attachment",
        "weight": 0.5
      },
      "ATTACHMENT_DOUBLE_EXTENSION": {
        "family": "attachment",
        "weight": 0.45
      },
      "ATTACHMENT_FILENAME_DECEPTION": {
        "family": "attachment",
        "weight": 0.4
      },
      "ATTACHMENT_MIME_MISMATCH": {
        "family": "attachment",
        "weight": 0.35
      },
      "ATTACHMENT_MAGIC_MISMATCH": {
        "family": "attachment",
        "weight": 0.45
      },
      "PDF_ACTIVE_METADATA": {
        "family": "attachment",
        "weight": 0.4
      },
      "ARCHIVE_INSPECTION": {
        "family": "attachment",
        "weight": 0.0
      },
      "ARCHIVE_DANGEROUS_MEMBER": {
        "family": "attachment",
        "weight": 0.5
      },
      "OFFICE_MACRO_MEMBER": {
        "family": "attachment",
        "weight": 0.5
      },
      "QR_ANALYSIS": {
        "family": "qr",
        "weight": 0.0
      },
      "QR_DECODE": {
        "family": "qr",
        "weight": 0.0
      },
      "URL_IOC_CHECK": {
        "family": "threat_intel",
        "weight": 0.0
      },
      "ATTACHMENT_IOC_CHECK": {
        "family": "threat_intel",
        "weight": 0.0
      },
      "IOC_MATCH": {
        "family": "threat_intel",
        "weight": 0.95
      },
      "IOC_DERIVED_DOMAIN": {
        "family": "threat_intel",
        "weight": 0.2
      },
      "BEC_REQUEST": {
        "family": "content_bec",
        "weight": 0.1
      }
    },
    "overrides": {
      "IOC_MATCH": {
        "min_score": 95.0,
        "min_confidence": 0.9
      }
    },
    "allow_partial_suspicious": true
  },
  "cache_sha256": "8de5049459335fec69bfcc3d18a1ed53e2f92e77f35fb80d9fb240dbbef716f0",
  "dev_manifest_sha256": "895e9ce0032d6a1886e8ebe3424716e9b91ab1ec35b8d54368a3ca6c5a7d281b",
  "canonical": 3462,
  "defender_skipped": 4,
  "attempted": 3458,
  "execution_errors": 2,
  "selection": {
    "id": "R2-F",
    "changes": {
      "ip_weight": 0.55,
      "phishing": 62,
      "bounded_partial_header": true
    },
    "reason": "43 additional phishing positives, 45 fewer abstentions, no additional PHISHING false positives; best coverage among candidates preserving 7 FP",
    "tradeoff": "3 benign REVIEW cases become SUSPICIOUS; 7 existing FP persist. DEV tuning does not establish TEST or production performance.",
    "justification": "IP literals occur in 70 phishing SUSPICIOUS and 18 phishing REVIEW cases. IP alone remains below PHISHING. Partial header exception requires local static risk >=0.35, completed corresponding analyzer, no non-header gaps, no failed tools or integrity errors. Lowering PHISHING to 60 is rejected: FP 7->27.",
    "selected_before_final_validation": true
  },
  "cost": {
    "llm": 0,
    "rag": 0,
    "virustotal": 0,
    "urlscan": 0
  },
  "safety": {
    "unknown_to_pass": false,
    "data_modified": false,
    "test_executed": 0
  },
  "validation": {
    "focused_pass": 86,
    "focused_fail": 0,
    "compile": "PASS",
    "ruff": "PASS"
  },
  "final_dev_replays": 1,
  "final_metrics": {
    "attempted": 3458,
    "successful": 3456,
    "execution_errors": 2,
    "labels": {
      "SAFE": 0,
      "SUSPICIOUS": 663,
      "PHISHING": 192,
      "NEEDS_ANALYST_REVIEW": 2601
    },
    "tp": 185,
    "tn": 481,
    "fp": 7,
    "fn": 182,
    "whole_dev": {
      "phishing_recall": {
        "value": 0.2612994350282486,
        "numerator": 185,
        "denominator": 708
      },
      "safe_fpr": {
        "value": 0.0025454545454545456,
        "numerator": 7,
        "denominator": 2750
      },
      "precision": {
        "value": 0.9635416666666666,
        "numerator": 185,
        "denominator": 192
      },
      "decision_coverage": {
        "value": 0.24739583333333334,
        "numerator": 855,
        "denominator": 3456
      },
      "abstention": {
        "value": 0.7526041666666666,
        "numerator": 2601,
        "denominator": 3456
      },
      "suspicious_rate": {
        "value": 0.1918402777777778,
        "numerator": 663,
        "denominator": 3456
      },
      "execution_error_rate": {
        "value": 0.000578368999421631,
        "numerator": 2,
        "denominator": 3458
      },
      "safe_precision": {
        "value": null,
        "numerator": 0,
        "denominator": 0
      }
    },
    "selective": {
      "precision": {
        "value": 0.9635416666666666,
        "numerator": 185,
        "denominator": 192
      },
      "recall": {
        "value": 0.5040871934604905,
        "numerator": 185,
        "denominator": 367
      },
      "f1": {
        "value": 0.6618962432915921,
        "numerator": 370,
        "denominator": 559
      },
      "accuracy": {
        "value": 0.7789473684210526,
        "numerator": 666,
        "denominator": 855
      },
      "fpr": {
        "value": 0.014344262295081968,
        "numerator": 7,
        "denominator": 488
      }
    }
  },
  "final_policy": {
    "version": 1,
    "thresholds": {
      "suspicious": 30.0,
      "phishing": 62.0
    },
    "required_signals": [
      "SPF_FAIL",
      "DKIM_FAIL",
      "DMARC_FAIL"
    ],
    "llm_weight_cap": 0.1,
    "families": {
      "email_auth": {
        "cap": 0.45
      },
      "identity": {
        "cap": 0.45
      },
      "url_deception": {
        "cap": 0.6
      },
      "attachment": {
        "cap": 0.5
      },
      "qr": {
        "cap": 0.0
      },
      "threat_intel": {
        "cap": 0.95
      },
      "content_bec": {
        "cap": 0.15
      }
    },
    "weights": {
      "SPF_FAIL": {
        "family": "email_auth",
        "weight": 0.25
      },
      "DKIM_FAIL": {
        "family": "email_auth",
        "weight": 0.35
      },
      "DMARC_FAIL": {
        "family": "email_auth",
        "weight": 0.45
      },
      "REPLY_TO_MISMATCH": {
        "family": "identity",
        "weight": 0.4
      },
      "RETURN_PATH_MISMATCH": {
        "family": "identity",
        "weight": 0.25
      },
      "DISPLAY_NAME_DOMAIN_MISMATCH": {
        "family": "identity",
        "weight": 0.25
      },
      "RECEIVED_CHAIN_ANOMALY": {
        "family": "identity",
        "weight": 0.2
      },
      "HREF_MISMATCH": {
        "family": "url_deception",
        "weight": 0.6
      },
      "URL_IP_LITERAL": {
        "family": "url_deception",
        "weight": 0.55
      },
      "URL_PUNYCODE": {
        "family": "url_deception",
        "weight": 0.2
      },
      "URL_LOOKALIKE": {
        "family": "url_deception",
        "weight": 0.5
      },
      "URL_EXCESSIVE_SUBDOMAIN": {
        "family": "url_deception",
        "weight": 0.25
      },
      "URL_SHORTENER": {
        "family": "url_deception",
        "weight": 0.2
      },
      "URL_SUSPICIOUS_PORT": {
        "family": "url_deception",
        "weight": 0.25
      },
      "URL_OBFUSCATED": {
        "family": "url_deception",
        "weight": 0.35
      },
      "HEADER_ANALYSIS": {
        "family": "identity",
        "weight": 0.0
      },
      "URL_ANALYSIS": {
        "family": "url_deception",
        "weight": 0.0
      },
      "ATTACHMENT_ANALYSIS": {
        "family": "attachment",
        "weight": 0.0
      },
      "ATTACHMENT_METADATA": {
        "family": "attachment",
        "weight": 0.0
      },
      "ATTACHMENT_EXECUTABLE": {
        "family": "attachment",
        "weight": 0.5
      },
      "ATTACHMENT_DOUBLE_EXTENSION": {
        "family": "attachment",
        "weight": 0.45
      },
      "ATTACHMENT_FILENAME_DECEPTION": {
        "family": "attachment",
        "weight": 0.4
      },
      "ATTACHMENT_MIME_MISMATCH": {
        "family": "attachment",
        "weight": 0.35
      },
      "ATTACHMENT_MAGIC_MISMATCH": {
        "family": "attachment",
        "weight": 0.45
      },
      "PDF_ACTIVE_METADATA": {
        "family": "attachment",
        "weight": 0.4
      },
      "ARCHIVE_INSPECTION": {
        "family": "attachment",
        "weight": 0.0
      },
      "ARCHIVE_DANGEROUS_MEMBER": {
        "family": "attachment",
        "weight": 0.5
      },
      "OFFICE_MACRO_MEMBER": {
        "family": "attachment",
        "weight": 0.5
      },
      "QR_ANALYSIS": {
        "family": "qr",
        "weight": 0.0
      },
      "QR_DECODE": {
        "family": "qr",
        "weight": 0.0
      },
      "URL_IOC_CHECK": {
        "family": "threat_intel",
        "weight": 0.0
      },
      "ATTACHMENT_IOC_CHECK": {
        "family": "threat_intel",
        "weight": 0.0
      },
      "IOC_MATCH": {
        "family": "threat_intel",
        "weight": 0.95
      },
      "IOC_DERIVED_DOMAIN": {
        "family": "threat_intel",
        "weight": 0.2
      },
      "BEC_REQUEST": {
        "family": "content_bec",
        "weight": 0.1
      }
    },
    "overrides": {
      "IOC_MATCH": {
        "min_score": 95.0,
        "min_confidence": 0.9
      }
    },
    "allow_partial_suspicious": true,
    "allow_partial_header_suspicious": true
  },
  "final_status": {
    "round2_complete": true,
    "dev_quality_improved": true,
    "ready_for_final_dev_validation": true,
    "ready_for_test": false,
    "remaining_blockers": [
      "DEV-only tuning; TEST generalization remains unmeasured",
      "Coverage gaps and 171 signal-free phishing abstentions remain"
    ]
  }
}
```
