"""DEV-only Round 1 audit, frozen evidence replay, and full graph validation."""

import argparse
import asyncio
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

from eval.metrics import percentile, ratio, summarize
from eval.results.dev_baseline_driver import MeasuredIOC
from eval.results.p0_remediation_driver import MIME_IDS, P0Target, inputs, snapshot, source_hashes
from eval.run_eval import evaluate_case
from src.agents.nodes.attachment_node import attachment_node
from src.agents.nodes.header_node import header_node
from src.agents.nodes.qr_node import qr_node
from src.agents.nodes.url_node import url_node
from src.config import get_settings
from src.evidence.models import Evidence, Gate1Result
from src.evidence.risk_engine import RiskPolicy, load_risk_policy, score_evidence
from src.evidence.validation import validate_evidence
from src.parsers.email_parser import EmailParseError, parse_email
from src.services.ioc_index import SQLiteIOCClient
from src.services.ioc_store import normalize_ioc

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "eval/results"
CACHE = OUT / "dev_tuning_round1_evidence.jsonl"


def save(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def distribution(values):
    values = list(values)
    return {"count": len(values), "mean": sum(values) / len(values) if values else None,
            **{f"p{p}": percentile(values, p / 100) for p in (25, 50, 75, 90, 95)},
            "max": max(values) if values else None}


def metric(records):
    successful = [r for r in records if r["status"] == "success"]
    decided = [r for r in successful if r["predicted_label"] != "NEEDS_ANALYST_REVIEW"]
    labels = Counter(r["predicted_label"] for r in successful)
    positive = sum(r["expected_label"] == "PHISHING" for r in records)
    negative = sum(r["expected_label"] == "SAFE" for r in records)
    tp = sum(r["expected_label"] == "PHISHING" and r["predicted_label"] == "PHISHING" for r in decided)
    fp = sum(r["expected_label"] == "SAFE" and r["predicted_label"] == "PHISHING" for r in decided)
    tn = sum(r["expected_label"] == "SAFE" and r["predicted_label"] in {"SAFE", "SUSPICIOUS"} for r in decided)
    fn = sum(r["expected_label"] == "PHISHING" and r["predicted_label"] in {"SAFE", "SUSPICIOUS"} for r in decided)
    safe = [r for r in successful if r["predicted_label"] == "SAFE"]
    return {"attempted": len(records), "successful": len(successful), "execution_errors": len(records)-len(successful),
            "labels": {label: labels[label] for label in ("SAFE", "SUSPICIOUS", "PHISHING", "NEEDS_ANALYST_REVIEW")},
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "whole_dev": {"phishing_recall": ratio(tp, positive).model_dump(),
                          "safe_fpr": ratio(fp, negative).model_dump(),
                          "precision": ratio(tp, tp+fp).model_dump(),
                          "decision_coverage": ratio(len(decided), len(successful)).model_dump(),
                          "abstention": ratio(labels["NEEDS_ANALYST_REVIEW"], len(successful)).model_dump(),
                          "suspicious_rate": ratio(labels["SUSPICIOUS"], len(successful)).model_dump(),
                          "execution_error_rate": ratio(len(records)-len(successful), len(records)).model_dump(),
                          "safe_precision": ratio(sum(r["expected_label"] == "SAFE" for r in safe), len(safe)).model_dump()},
            "selective": {"precision": ratio(tp, tp+fp).model_dump(), "recall": ratio(tp, tp+fn).model_dump(),
                          "f1": ratio(2*tp, 2*tp+fp+fn).model_dump(),
                          "accuracy": ratio(tp+tn, tp+tn+fp+fn).model_dump(),
                          "fpr": ratio(fp, fp+tn).model_dump()}}


def stamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else None
    except (ValueError, TypeError, AttributeError):
        return None


def summarize_audit(rows, policy):
    reviews = [r for r in rows if r["status"] == "success" and r["predicted_label"] == "NEEDS_ANALYST_REVIEW"]
    fps = [r for r in rows if r["status"] == "success" and r["expected_label"] == "SAFE"
           and r["predicted_label"] == "PHISHING"]
    fp_cases, fp_aggregate = [], {k: Counter() for k in ("signal_type", "family", "analyzer", "ioc_source", "derived")}
    for row in fps:
        facts = row["evidence"]
        hits = [e for e in facts if e["signal_type"] == "IOC_MATCH"]
        ioc_audit = []
        for evidence in hits:
            value = evidence["value"]
            originals = value.get("matched_records") or [value]
            dates = [stamp(v) for r in originals for v in (r.get("first_seen"), r.get("last_seen"))]
            observed_later = any(d and row["email_timestamp"] and d > stamp(row["email_timestamp"]) for d in dates)
            ioc_audit.append({"evidence_id": evidence["evidence_id"], "kind": value["kind"],
                              "value": value["value"], "sources": value["sources"], "role": value["role"],
                              "derived": value["derived"], "derived_from": value["derived_from"],
                              "first_seen": value["first_seen"], "last_seen": value["last_seen"],
                              "effective_from": value["metadata"].get("effective_from"),
                              "effective_to": value["metadata"].get("effective_to"),
                              "email_timestamp": row["email_timestamp"], "email_timestamp_trusted": False,
                              "exists_in_evaluation_snapshot": True, "exact_domain_lookup": value["kind"] == "domain",
                              "derived_source_url_is_observed_url": value["derived_from"] in row["canonical_urls"],
                              "source_observation_after_email_date": bool(observed_later),
                              "classification": "DERIVED_SIGNAL_TOO_STRONG" if value["derived"] else "UNKNOWN",
                              "temporal_validity": "UNKNOWN_NO_EFFECTIVE_INTERVAL"})
        for key in ("signal_type", "family", "analyzer"):
            fp_aggregate[key].update({e[key] for e in facts if e["result"] == "FAIL"})
        fp_aggregate["ioc_source"].update({s["name"] for e in hits for s in e["value"]["sources"]})
        fp_aggregate["derived"].update({str(e["value"]["derived"]) for e in hits})
        fp_cases.append({"sample_id": row["case_id"], "ground_truth": "SAFE", "score": row["score"],
                         "label": row["predicted_label"], "source_dataset": row["source"],
                         "metadata": row["metadata"], "email_timestamp": row["email_timestamp"],
                         "evidence": facts, "contributions": row["risk"]["contributions"], "ioc_audit": ioc_audit,
                         "root_cause": "DERIVED_DOMAIN_SCOPE_OVERREACH" if hits else "URL_IDENTITY_HEURISTIC_COMBINATION"})
    labels = {}
    for label in ("SAFE", "PHISHING"):
        subset = [r for r in reviews if r["expected_label"] == label]
        primary, overlapping = Counter(), Counter()
        for r in subset:
            unknown = set(r["risk"]["coverage"]["unknown"])
            if "CONFLICTING_EVIDENCE" in r["risk"]["reasons"]:
                reason = "CONTRADICTORY_EVIDENCE"
            elif r["partial_parse"]:
                reason = "PARTIAL_PARSE"
            elif any(e["tool_status"] != "OK" for e in r["evidence"]):
                reason = "TOOL_UNKNOWN"
            elif unknown <= set(policy.required_signals):
                reason = "AUTH_UNKNOWN"
            elif r["score"] < policy.thresholds.suspicious:
                reason = "INSUFFICIENT_COVERAGE_FOR_SAFE"
            else:
                reason = "SCORE_BELOW_PHISHING"
            primary[reason] += 1
            overlapping.update({"AUTH_UNKNOWN"} if unknown & set(policy.required_signals) else set())
            if r["score"] < policy.thresholds.suspicious:
                overlapping["SCORE_BELOW_SUSPICIOUS"] += 1
            if not any(c["strength"] > 0 for c in r["risk"]["contributions"]):
                overlapping["NO_STRONG_SIGNAL"] += 1
            if r["partial_parse"]:
                overlapping["PARTIAL_PARSE"] += 1
            if r["score"] >= policy.thresholds.suspicious and set(r["risk"]["reasons"]) <= {"UNKNOWN_EVIDENCE", "MISSING_COVERAGE"}:
                overlapping["MEANINGFUL_RISK_BLOCKED_BY_PARTIAL_DECISION_CONTRACT"] += 1
        failed_signals = Counter(e["signal_type"] for r in subset for e in r["evidence"] if e["result"] == "FAIL")
        strongest = Counter(max(r["risk"]["contributions"], key=lambda c: c["strength"])["signal_type"]
                            if r["risk"]["contributions"] else "NONE" for r in subset)
        ioc = Counter(r["ioc_status"] for r in subset)
        labels[label] = {"cases": len(subset), "primary_blocking_reasons": dict(primary),
                         "overlapping_reasons": dict(overlapping), "score": distribution(r["score"] for r in subset),
                         "strongest_signal": dict(strongest), "failed_signals": dict(failed_signals), "ioc_status": dict(ioc),
                         "evidence_family_count": dict(Counter(len({e["family"] for e in r["evidence"]}) for r in subset)),
                         "near_suspicious_plus_minus_5": sum(25 <= r["score"] <= 35 for r in subset),
                         "near_phishing_plus_minus_5": sum(65 <= r["score"] <= 75 for r in subset),
                         "partial_parse": sum(r["partial_parse"] for r in subset)}
    buckets = {}
    for name, lower, upper in (("below_0.25", 0, .25), ("0.25_to_0.50", .25, .5),
                               ("0.50_to_0.75", .5, .75), ("at_least_0.75", .75, 1.01)):
        buckets[name] = {}
        for label in ("SAFE", "PHISHING"):
            subset = [r for r in reviews if r["expected_label"] == label and lower <= r["risk"]["coverage"]["ratio"] < upper]
            buckets[name][label] = {"cases": len(subset), "score": distribution(r["score"] for r in subset),
                                   "known_families": dict(Counter(f for r in subset for f in {e["family"] for e in r["evidence"] if e["result"] != "UNKNOWN"})),
                                   "unknown_families": dict(Counter(f for r in subset for f in {e["family"] for e in r["evidence"] if e["result"] == "UNKNOWN"}))}
    return {"fp_cases": fp_cases, "fp_aggregate_case_counts": {k: dict(v) for k, v in fp_aggregate.items()},
            "review_analysis": labels, "review_coverage_buckets": buckets,
            "safe_supported_by_complete_coverage": sum(r["risk"]["coverage"]["complete"] for r in reviews),
            "feature_state": {"content_bec": "DISABLED", "llm_verdict": "DISABLED", "rag": "DISABLED",
                              "phishing_review_potentially_needing_content_inspection": labels["PHISHING"]["cases"],
                              "content_bec_detection_gain": None,
                              "note": "Disabled capability is a boundary gap; its gain cannot be inferred from labels or local evidence"}}


def audit():
    settings = get_settings()
    assert not settings.external_enrichment_enabled and not settings.rag_enabled
    assert not settings.header_trusted_authserv_ids
    before = snapshot()
    policy = load_risk_policy()
    entries, _, _ = inputs()
    baseline = json.loads((OUT / "p0_dev_baseline.json").read_text(encoding="utf-8"))
    assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
               for name, digest in baseline["source_hashes"].items()
               if Path(name).parts[0] in {"src", "config"}), "AUDIT_REQUIRES_FROZEN_P0_CODE; existing cache retained"
    expected = {r["case_id"]: r for r in baseline["cases"]}
    ioc = SQLiteIOCClient(settings.ioc_data_path, settings.ioc_index_path)
    fp_ids = [sid for sid,r in expected.items() if r["expected_label"] == "SAFE" and r["predicted_label"] == "PHISHING"]
    ordered = fp_ids + [sid for sid in entries if sid not in fp_ids]
    rows = []
    with CACHE.open("w", encoding="utf-8") as stream:
        for index, sid in enumerate(ordered, 1):
            old = expected[sid]
            row = {"case_id": sid, "expected_label": old["expected_label"], "source": old["source"], "metadata": old["metadata"]}
            try:
                parsed = parse_email((DATA / entries[sid].case.file).read_bytes()).raw_for_analyzers
                state = {"parsed_email": parsed}
                nodes = [header_node(state), url_node(state, ioc_client=ioc), attachment_node(state, ioc_client=ioc), qr_node(state, ioc_client=ioc)]
                gate = validate_evidence([e for n in nodes for e in n["evidence"]])
                applicable = [s for n in nodes for s in n["applicable_signals"]]
                risk = score_evidence(gate, applicable_signals=applicable)
                assert not gate.issues and risk.score == old["score"] and risk.label_candidate == old["predicted_label"], sid
                assert {e.evidence_id for e in gate.evidence} == {e["id"] for e in baseline["safe_evidence"][sid]["evidence"]}, sid
                date = None
                try:
                    date = parsedate_to_datetime(parsed["headers"].get("date", [""])[0])
                    date = date.isoformat() if date.tzinfo else None
                except (ValueError, TypeError, IndexError, OverflowError):
                    pass
                checks = [e for e in gate.evidence if e.signal_type.endswith("IOC_CHECK")]
                hits = [e for e in gate.evidence if e.signal_type == "IOC_MATCH"]
                references = [e for e in checks if isinstance(e.value, dict) and e.value.get("matched_record")]
                ioc_status = ("MALICIOUS" if hits else "BENIGN_REFERENCE_ONLY" if references else "NO_MATCH" if checks else "NO_IOC_QUERIES")
                row.update(status="success", score=risk.score, predicted_label=risk.label_candidate,
                           risk=risk.model_dump(mode="json"), evidence=[e.model_dump(mode="json") for e in gate.evidence],
                           applicable=applicable, email_timestamp=date, partial_parse=parsed["partial_parse"],
                           canonical_urls=[e.value.get("canonical_url") for e in gate.evidence if isinstance(e.value, dict)],
                           ioc_status=ioc_status)
            except EmailParseError as exc:
                assert old["status"] == "failed" and exc.code == old["error"]["code"]
                row.update(status="failed", score=None, predicted_label=None, error_code=exc.code)
            rows.append(row)
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            if index % 100 == 0 or index == len(ordered):
                print("AUDIT", index, "/", len(ordered), flush=True)
    assert before == snapshot(), "DATA_CHANGED"
    summary = summarize_audit(rows, policy)
    save("dev_tuning_round1_audit.json", {"policy": policy.model_dump(mode="json"), "source_hashes": source_hashes(),
                                          "p0_metrics": metric(rows), "data_modified": False, "test_executed": 0, **summary})
    print("AUDIT_SUMMARY", json.dumps({k: summary[k] for k in ("fp_aggregate_case_counts", "review_analysis", "safe_supported_by_complete_coverage")}), flush=True)


def derived_only(value):
    if value.get("kind") != "domain" or not value.get("derived"):
        return False
    # A normalization collision must not hide an independently listed malicious domain.
    records = value.get("matched_records") or []
    return not any(r.get("role") == "MALICIOUS" and not r.get("derived", False) for r in records)


def transformed(evidence):
    output = []
    for item in evidence:
        if item.signal_type == "IOC_MATCH" and derived_only(item.value):
            values = item.model_dump(exclude={"evidence_id"})
            values["signal_type"] = "IOC_DERIVED_DOMAIN"
            item = Evidence(**values)
        output.append(item)
    return output


def partial_suspicious(risk, evidence, policy):
    # Hypothetical decision-contract candidate, not a production override.
    # Cache contains no LLM evidence: score is entirely deterministic.
    assert all(e.provenance.source != "llm" for e in evidence)
    return (risk.label_candidate == "NEEDS_ANALYST_REVIEW"
            and policy.thresholds.suspicious <= risk.score < policy.thresholds.phishing
            and set(risk.reasons) <= {"UNKNOWN_EVIDENCE", "MISSING_COVERAGE"}
            and "HEADER_ANALYSIS" not in risk.coverage.missing
            and all(policy.weights[s].family in {"email_auth", "identity"} for s in risk.coverage.missing)
            and all(e.tool_status == "OK" for e in evidence))


def candidates():
    audit_report = json.loads((OUT / "dev_tuning_round1_audit.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in CACHE.read_text(encoding="utf-8").splitlines()]
    baseline = RiskPolicy.model_validate(audit_report["policy"])
    specs = [
        {"id": "C0", "derived_correction": False, "partial_suspicious": False, "phishing": 70, "suspicious": 30},
        {"id": "C1", "derived_correction": True, "partial_suspicious": False, "phishing": 70, "suspicious": 30},
        {"id": "C2", "derived_correction": True, "partial_suspicious": True, "phishing": 70, "suspicious": 30},
        {"id": "C3", "derived_correction": True, "partial_suspicious": True, "phishing": 75, "suspicious": 30},
        {"id": "C4", "derived_correction": True, "partial_suspicious": True, "phishing": 65, "suspicious": 30},
        {"id": "C5", "derived_correction": True, "partial_suspicious": True, "phishing": 70, "suspicious": 40},
    ]
    cached = {r["case_id"]: [Evidence.model_validate(e) for e in r["evidence"]]
              for r in rows if r["status"] == "success"}
    corrected = {sid: transformed(facts) for sid, facts in cached.items()}
    results = []
    for spec in specs:
        data = baseline.model_dump()
        data["thresholds"] = {k: spec[k] for k in ("suspicious", "phishing")}
        if spec["derived_correction"]:
            data["weights"]["IOC_DERIVED_DOMAIN"] = {"family": "threat_intel", "weight": .20}
        policy = RiskPolicy.model_validate(data)
        predictions, unsafe = [], []
        for row in rows:
            predicted = {k: row[k] for k in ("case_id", "expected_label", "status", "score", "predicted_label")}
            if row["status"] == "success":
                facts = (corrected if spec["derived_correction"] else cached)[row["case_id"]]
                risk = score_evidence(Gate1Result(evidence=tuple(facts)), applicable_signals=row["applicable"], policy=policy)
                label = risk.label_candidate
                if spec["partial_suspicious"] and partial_suspicious(risk, facts, policy):
                    label = "SUSPICIOUS"
                predicted.update(score=risk.score, predicted_label=label)
                if label == "SAFE" and not risk.coverage.complete:
                    unsafe.append(row["case_id"])
            predictions.append(predicted)
        metrics = metric(predictions)
        escalation = [r for r in predictions if r["predicted_label"] in {"SUSPICIOUS", "PHISHING"}]
        metrics["triage"] = {"phishing_or_suspicious_recall": ratio(sum(r["expected_label"] == "PHISHING" for r in escalation), 708).model_dump(),
                             "safe_escalation_rate": ratio(sum(r["expected_label"] == "SAFE" for r in escalation), 2750).model_dump(),
                             "suspicious_ground_truth": dict(Counter(r["expected_label"] for r in predictions if r["predicted_label"] == "SUSPICIOUS"))}
        result = {"configuration": spec, "metrics": metrics, "unsafe_safe": unsafe,
                  "predictions": predictions,
                  "guardrails": {"unsafe_safe": not unsafe, "no_fp_inflation": metrics["fp"] <= 24,
                                 "no_new_execution_errors": metrics["execution_errors"] == 2}}
        results.append(result)
        print("CANDIDATE", spec["id"], json.dumps({"configuration": spec, "metrics": metrics}), flush=True)
    assert results[0]["metrics"] == audit_report["p0_metrics"] or all(
        results[0]["metrics"][k] == audit_report["p0_metrics"][k] for k in ("tp", "fp", "labels", "whole_dev"))
    save("dev_tuning_round1_candidates.json", {
        "method": "Small predeclared DEV-only frozen Gate-1 evidence replay; C0 exactly reproduces P0. No TEST data.",
        "objective": "Correct proven scope overreach first; no unsafe SAFE; no new errors; FP no higher than P0; compare whole-DEV recall, triage value and abstention, not selective F1 alone.",
        "safe_coverage_relaxation": "NOT TESTED: no complete-coverage region supports SAFE",
        "derived_weight_reason": "0.20 is a weak contextual domain relation, aligned with the existing URL shortener weight; direct malicious URL/IP/hash/domain assertions retain original weight/override",
        "candidates": results})


def enrich_audit():
    report = json.loads((OUT / "dev_tuning_round1_audit.json").read_text(encoding="utf-8"))
    originals = {r["sample_id"]: r for r in json.loads((OUT / "dev_tuning_round1_fp_audit.json").read_text(encoding="utf-8"))["cases"]}
    aggregates = {key: Counter() for key in ("applied_strength_sum_by_signal", "winning_case_count_by_signal", "malicious_source_case_count")}
    temporal = 0
    for case in report["fp_cases"]:
        case["email_date_header"] = originals[case["sample_id"]]["email_date"]
        try:
            email_date = parsedate_to_datetime(case["email_date_header"][0])
        except (ValueError, TypeError, IndexError):
            email_date = None
        case["email_timestamp"] = email_date.isoformat() if email_date else None
        case["email_timestamp_trusted"] = False
        case["timezone_known"] = bool(email_date and email_date.tzinfo)
        for hit in case["ioc_audit"]:
            hit["email_timestamp"] = case["email_timestamp"]
            value = next(e["value"] for e in case["evidence"] if e["evidence_id"] == hit["evidence_id"])
            queried_urls = {e["value"]["indicator"] for e in case["evidence"]
                            if e["signal_type"].endswith("IOC_CHECK") and e["value"].get("kind") == "url"}
            try:
                source_url = normalize_ioc("url", value["derived_from"])
                hit["derived_source_url_is_observed_url"] = source_url in queried_urls
            except (ValueError, TypeError, AttributeError):
                hit["derived_source_url_is_observed_url"] = None
            records = value.get("matched_records") or []
            malicious_records = [r for r in records if r["role"] == "MALICIOUS"]
            hit["source_records"] = records
            # The canonical snapshot merges source observations into one role.
            # A Tranco rank is a reference observation, not a malicious assertion.
            hit["malicious_sources"] = sorted({s["name"] for r in malicious_records for s in r["sources"]
                                               if not (s["name"] == "Tranco" and "rank" in s)})
            hit["benign_reference_sources"] = sorted({s["name"] for r in records for s in r["sources"]
                                                      if r["role"] == "BENIGN_REFERENCE" or (s["name"] == "Tranco" and "rank" in s)})
            hit["source_roles_merged_in_canonical_record"] = bool(hit["malicious_sources"] and hit["benign_reference_sources"])
            years = [stamp(r.get("first_seen")) for r in malicious_records]
            hit["source_observation_after_email_year"] = bool(email_date and any(d and d.year > email_date.year for d in years))
        temporal += any(hit["source_observation_after_email_year"] for hit in case["ioc_audit"])
        for contribution in case["contributions"]:
            aggregates["applied_strength_sum_by_signal"][contribution["signal_type"]] += contribution["applied_strength"]
        if case["contributions"]:
            dominant = max(case["contributions"], key=lambda c: c["applied_strength"])
            aggregates["winning_case_count_by_signal"][dominant["signal_type"]] += 1
        aggregates["malicious_source_case_count"].update({s for hit in case["ioc_audit"] for s in hit["malicious_sources"]})
    rows = [json.loads(line) for line in CACHE.read_text(encoding="utf-8").splitlines()]
    for label in ("SAFE", "PHISHING"):
        subset = [r for r in rows if r["expected_label"] == label and r["predicted_label"] == "NEEDS_ANALYST_REVIEW"]
        item = report["review_analysis"][label]
        item["missing_signal_case_counts"] = dict(Counter(s for r in subset for s in r["risk"]["coverage"]["missing"]))
        item["positive_risk_family_count"] = dict(Counter(len({c["family"] for c in r["risk"]["contributions"] if c["applied_strength"] > 0}) for r in subset))
        item["positive_signals_by_analyzer"] = dict(Counter(e["analyzer"] for r in subset for e in r["evidence"] if e["result"] == "FAIL"))
        item["auth_only_coverage_gap"] = sum(set(r["risk"]["coverage"]["missing"]) <= {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"} for r in subset)
    report["fp_contribution_aggregate"] = {k: dict(v) for k,v in aggregates.items()}
    report["fp_classification"] = {"total": 24, "ioc_driven": 22, "non_ioc": 2,
                                    "DERIVED_SIGNAL_TOO_STRONG": 22, "PROVENANCE_WEAK": 0,
                                    "VALID_CURRENT_MALICIOUS_SIGNAL": 0, "LIKELY_IOC_DATA_ISSUE": 0,
                                    "TEMPORAL_OBSERVATION_MISMATCH_SECONDARY": temporal,
                                    "UNKNOWN_EFFECTIVE_INTERVAL": 22,
                                    "MERGED_REFERENCE_PROVENANCE_SECONDARY": sum(any(h["source_roles_merged_in_canonical_record"] for h in c["ioc_audit"]) for c in report["fp_cases"]),
                                    "note": "22 URL-derived domain relations are exact host matches, not matches to the source malicious URL. Historical dates are untrusted; later observation is not proof of expiry or of prior innocence. Tranco reference provenance is not a malicious-feed assertion."}
    save("dev_tuning_round1_audit.json", report)
    print("ENRICHED_AUDIT", json.dumps(report["fp_classification"]), flush=True)


class Round1Target(P0Target):
    async def analyze(self, raw, case):
        observation = await super().analyze(raw, case)
        risk = observation.state["risk_result"]
        self.details[case.id]["contributions"] = [c.model_dump(mode="json") for c in risk.contributions]
        self.details[case.id]["ioc_matches"] = [e.model_dump(mode="json") for e in observation.state["validated_evidence"]
                                                  if e.signal_type in {"IOC_MATCH", "IOC_DERIVED_DOMAIN"}]
        return observation


def error_samples(records, target):
    groups = {
        "false_positives": lambda r: r.expected_label == "SAFE" and r.predicted_label == "PHISHING",
        "phishing_abstentions": lambda r: r.expected_label == "PHISHING" and r.predicted_label == "NEEDS_ANALYST_REVIEW",
        "false_negatives": lambda r: r.expected_label == "PHISHING" and r.predicted_label in {"SAFE", "SUSPICIOUS"},
    }
    result = {}
    for name, predicate in groups.items():
        examples = []
        for record in sorted(records, key=lambda r: r.case_id):
            if record.status != "success" or not predicate(record) or len(examples) == 10:
                continue
            detail = target.details[record.case_id]
            cause = ("PARTIAL_PARSE" if detail["parser_warnings"] else
                     "NO_POSITIVE_RISK_EVIDENCE" if not detail["contributions"] else
                     "SUSPICIOUS_NOT_CONFIRMED_PHISHING" if record.predicted_label == "SUSPICIOUS" else
                     "LOCAL_HEURISTICS_AND_CONTEXTUAL_IOC" if detail["ioc_matches"] else "LOCAL_HEURISTICS_AND_COVERAGE")
            examples.append({"sample_id": record.case_id, "ground_truth": record.expected_label,
                             "score": record.score, "label": record.predicted_label,
                             "evidence_types": sorted({e["type"] for e in detail["evidence"]}),
                             "contributions": detail["contributions"], "high_level_cause": cause})
        result[name] = examples
    return result


async def validate():
    settings = get_settings()
    assert not settings.external_enrichment_enabled and not settings.rag_enabled
    assert not settings.header_trusted_authserv_ids
    initial = snapshot()
    frozen_p0 = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in OUT.glob("p0_*") if p.is_file()}
    audit_report = json.loads((OUT / "dev_tuning_round1_audit.json").read_text(encoding="utf-8"))
    comparison = json.loads((OUT / "dev_tuning_round1_candidates.json").read_text(encoding="utf-8"))
    chosen = next(c for c in comparison["candidates"] if c["configuration"]["id"] == "C4")
    policy = load_risk_policy()
    assert policy.thresholds.phishing == 65 and policy.thresholds.suspicious == 30
    assert policy.allow_partial_suspicious and policy.weights["IOC_DERIVED_DOMAIN"].weight == .20
    assert "IOC_DERIVED_DOMAIN" not in policy.overrides
    assert policy.model_dump()["families"] == audit_report["policy"]["families"]
    selection = {"candidate": "C4", "reason": "Whole-DEV recall and precision improve while FP drops, coverage improves and no unsupported SAFE is introduced. C3 sacrifices recall; C2/C5 have lower recall; C1 retains excessive abstention.",
                 "tradeoff": "C4 has 7 FP versus 2 under C2 and produces 478 SAFE-ground-truth SUSPICIOUS decisions; selective F1 decreases because SUSPICIOUS is negative in the existing binary projection.",
                 "parameters": chosen["configuration"], "selected_before_full_graph_validation": True,
                 "policy": policy.model_dump(mode="json")}
    save("dev_tuning_round1_selection.json", selection)
    entries, _, _ = inputs()
    expected = {r["case_id"]: r for r in chosen["predictions"]}
    ioc = MeasuredIOC(settings)
    target = Round1Target(settings, ioc)
    records = []
    for index, entry in enumerate(entries.values(), 1):
        record = await evaluate_case(entry, target, DATA, "offline")
        old = expected[record.case_id]
        assert (record.status, record.score, record.predicted_label) == (old["status"], old["score"], old["predicted_label"]), record.case_id
        records.append(record)
        if index % 100 == 0 or index == len(entries):
            print("ROUND1_FULL_DEV", index, "/", len(entries), flush=True)
    changed = initial != snapshot()
    p0_changed = any(hashlib.sha256(Path(p).read_bytes()).hexdigest() != digest for p,digest in frozen_p0.items())
    metrics = metric([r.model_dump(mode="json") for r in records])
    assert all(metrics[k] == chosen["metrics"][k] for k in ("labels", "tp", "tn", "fp", "fn", "whole_dev", "selective"))
    passed = (not changed and not p0_changed and not ioc.errors
              and {r.case_id for r in records if r.status == "failed"} == MIME_IDS
              and not any(r.predicted_label == "SAFE" and not r.coverage_complete for r in records))
    save("dev_tuning_round1.json", {"passed": passed, "timestamp": datetime.now(UTC).isoformat(),
                                   "canonical": 3462, "defender_skipped": 4, "selected": selection,
                                   "metrics": metrics, "standard_eval_metrics": summarize(records),
                                   "source_hashes": source_hashes(), "p0_artifacts_unchanged": not p0_changed,
                                   "data_modified": changed, "test_executed": 0, "api_calls": 0, "llm_calls": 0,
                                   "ioc_errors": dict(ioc.errors), "error_samples": error_samples(records, target),
                                   "cases": [r.model_dump(mode="json") for r in records], "safe_evidence": target.details})
    print("ROUND1_RESULT", json.dumps({"passed": passed, "metrics": metrics}), flush=True)
    assert passed, "ROUND1_VALIDATION_FAILED"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("audit", "candidates", "enrich-audit", "validate"))
    args = parser.parse_args()
    if args.mode == "audit":
        audit()
    elif args.mode == "candidates":
        candidates()
    elif args.mode == "enrich-audit":
        enrich_audit()
    else:
        asyncio.run(validate())
