"use client";
import { useState, type FormEvent } from "react";
import { api } from "../../lib/api";
import { ACTION_KINDS, type ActionKind, type Case } from "../../lib/types";
import { ErrorNotice } from "../ui/Feedback";
import { formatDate } from "../../utils/format";
import { defangText } from "../../utils/defang";

export function ActionAuthorization({ caseData, onChanged }: { caseData: Case; onChanged: () => Promise<void> }) {
  const [kind, setKind] = useState<ActionKind>("QUARANTINE");
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false); const [error, setError] = useState<Error | null>(null);
  async function propose(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(null);
    try { await api.propose(caseData.case_id, kind); await onChanged(); }
    catch (cause) { setError(cause instanceof Error ? cause : new Error("Không đề xuất được action.")); }
    finally { setBusy(false); }
  }
  async function authorize(event: FormEvent<HTMLFormElement>, id: string) {
    event.preventDefault(); const reason = reasons[id]?.trim(); if (!reason || busy) return;
    setBusy(true); setError(null);
    try { await api.authorize(caseData.case_id, id, reason); await onChanged(); }
    catch (cause) { setError(cause instanceof Error ? cause : new Error("Không authorize được action.")); }
    finally { setBusy(false); }
  }
  return <section className="panel"><h2>Action authorization</h2><p className="muted">Chỉ lưu proposal và authorization. Không thực thi quarantine, block hoặc delete.</p>
    <ErrorNotice error={error} /><form onSubmit={propose} className="inline-form"><label>Action kind<select disabled={busy} value={kind} onChange={e => setKind(e.target.value as ActionKind)}>{ACTION_KINDS.map(value => <option key={value}>{value}</option>)}</select></label>
      <button disabled={busy || caseData.actions.some(item => item.kind === kind)}>Đề xuất action</button></form>
    {caseData.actions.length === 0 && <p className="empty">Chưa có action proposal.</p>}
    {caseData.actions.map(action => {
      const allowed = caseData.review_status === "APPROVED" || (caseData.review_status === "MODIFIED" && caseData.allowed_actions.includes(action.kind));
      return <article className="action-row" key={action.action_id}><p><strong>{action.kind}</strong> · <code>{action.state}</code></p>
        {action.state === "PROPOSED" ? <form onSubmit={event => void authorize(event, action.action_id)}><label>Authorization reason<input maxLength={2000} required disabled={busy || !allowed} value={reasons[action.action_id] ?? ""} onChange={e => setReasons(current => ({ ...current, [action.action_id]: e.target.value }))} /></label>
          <button disabled={busy || !allowed || !reasons[action.action_id]?.trim()}>Authorize {action.kind}</button>{!allowed && <p className="muted">Review hiện tại chưa cho phép authorize action này.</p>}</form>
          : <p>Authorized by <code>{action.authorized_by ?? "—"}</code> · {formatDate(action.authorized_at)}<br />{defangText(action.authorization_reason ?? "")}</p>}
      </article>;
    })}
  </section>;
}
