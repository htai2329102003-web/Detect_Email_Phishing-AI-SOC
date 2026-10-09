"use client";
import { useState } from "react";
import { useResource } from "../../hooks/useResource";
import type { AuditEntry } from "../../lib/types";
import { casePath } from "../../lib/api";
import { defangText, safeJson } from "../../utils/defang";
import { formatDate } from "../../utils/format";
import { ErrorNotice, Loading, Pager } from "../ui/Feedback";

export function AuditTable({ entries }: { entries: AuditEntry[] }) {
  if (!entries.length) return <p className="empty">Chưa có audit event trên trang này.</p>;
  return <div className="table-scroll"><table><thead><tr><th>Time / event</th><th>Actor</th><th>Old → new</th><th>Reason / metadata</th></tr></thead><tbody>
    {entries.map(row => <tr key={row.audit_id}><td>{formatDate(row.timestamp)}<small>{defangText(row.event)}</small></td><td className="mono small">{row.actor_id}</td>
      <td>{row.old_state ?? "—"} → {row.new_state ?? "—"}</td><td>{row.reason ? defangText(row.reason) : "—"}<details><summary>Metadata</summary><pre>{safeJson(row.event_metadata)}</pre></details></td></tr>)}
  </tbody></table></div>;
}
export function ReviewHistory({ caseId }: { caseId: string }) {
  const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useResource<AuditEntry[]>(`${casePath(caseId)}/audit?limit=50&offset=${offset}`);
  return <section className="panel"><div className="section-heading"><h2>Review / audit history</h2><button disabled={loading} onClick={() => void reload()}>Tải lại audit</button></div>
    <ErrorNotice error={error} />{loading ? <Loading /> : data && <><AuditTable entries={data} /><Pager offset={offset} size={50} count={data.length} onChange={setOffset} /></>}
  </section>;
}
