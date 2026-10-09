import Link from "next/link";
import type { CaseSummary } from "../../lib/types";
import { defangText } from "../../utils/defang";
import { formatDate } from "../../utils/format";
import { VerdictBadge } from "../analysis/VerdictBadge";
export function CaseTable({ cases }: { cases: CaseSummary[] }) {
  if (!cases.length) return <p className="empty">Chưa có case trên trang này.</p>;
  return <div className="table-scroll"><table><thead><tr><th>Case / filename</th><th>AI score / label</th><th>Review status</th><th>Created</th><th>Reviewer</th></tr></thead><tbody>
    {cases.map(item => <tr key={item.case_id}><td><Link className="mono" href={`/cases/${encodeURIComponent(item.case_id)}`}>{item.case_id}</Link><small>{defangText(item.original_filename)}</small></td>
      <td>{item.risk_score}/100 <VerdictBadge verdict={item.label_candidate} /></td><td><VerdictBadge verdict={item.review_status} /></td><td>{formatDate(item.created_at)}</td>
      <td className="mono small">{item.reviewer_id ?? "—"}</td></tr>)}
  </tbody></table></div>;
}
