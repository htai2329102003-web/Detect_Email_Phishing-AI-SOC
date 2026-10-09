"use client";
import { useState, type FormEvent } from "react";
import { api } from "../../lib/api";
import { ACTION_KINDS, RISK_LABELS, type ActionKind, type Case, type ReviewRequest, type RiskLabel } from "../../lib/types";
import { ErrorNotice } from "../ui/Feedback";

export function ReviewActions({ caseData, onChanged }: { caseData: Case; onChanged: () => Promise<void> }) {
  const [decision, setDecision] = useState<ReviewRequest["decision"]>("APPROVE");
  const [reason, setReason] = useState(""); const [summary, setSummary] = useState("");
  const [label, setLabel] = useState<RiskLabel>("NEEDS_ANALYST_REVIEW");
  const [allowedActions, setAllowedActions] = useState<ActionKind[]>([]);
  const [busy, setBusy] = useState(false); const [error, setError] = useState<Error | null>(null);
  if (caseData.review_status !== "PENDING") return <p className="notice">Case đã final. Không thể review lại.</p>;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (busy) return;
    setBusy(true); setError(null);
    const body: ReviewRequest = decision === "MODIFY"
      ? { decision, reason: reason.trim(), analyst_assessment: { label, summary: summary.trim() }, allowed_actions: allowedActions }
      : { decision, ...(reason.trim() ? { reason: reason.trim() } : {}) };
    try { await api.review(caseData.case_id, body); await onChanged(); }
    catch (cause) { setError(cause instanceof Error ? cause : new Error("Không lưu được review.")); }
    finally { setBusy(false); }
  }
  const invalid = decision === "MODIFY" && (!reason.trim() || !summary.trim());
  return <form onSubmit={submit} aria-label="Analyst review actions"><fieldset disabled={busy}>
    <legend>Quyết định analyst</legend><div className="choice-row">{(["APPROVE", "REJECT", "MODIFY"] as const).map(value => <label key={value} className="choice">
      <input type="radio" name="decision" value={value} checked={decision === value} onChange={() => setDecision(value)} />{value}</label>)}</div>
    <label>Reason {decision === "MODIFY" ? "(bắt buộc)" : "(tuỳ chọn)"}<textarea maxLength={2000} required={decision === "MODIFY"} value={reason} onChange={e => setReason(e.target.value)} /></label>
    {decision === "MODIFY" && <><label>Analyst label<select value={label} onChange={e => setLabel(e.target.value as RiskLabel)}>{RISK_LABELS.map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Analyst summary<textarea required maxLength={4000} value={summary} onChange={e => setSummary(e.target.value)} /></label>
      <fieldset><legend>Cho phép authorize sau MODIFY (tuỳ chọn)</legend><div className="choice-row">{ACTION_KINDS.map(kind => <label key={kind} className="choice">
        <input type="checkbox" checked={allowedActions.includes(kind)} onChange={e => setAllowedActions(current => e.target.checked ? [...current, kind] : current.filter(item => item !== kind))} />{kind}</label>)}</div></fieldset></>}
    <p className="muted">Review sẽ final case. AI score và evidence giữ nguyên. Authorization action vẫn cần thao tác riêng.</p>
    <ErrorNotice error={error} /><button className="primary" disabled={busy || invalid}>{busy ? "Đang lưu review…" : "Xác nhận review"}</button>
  </fieldset></form>;
}
