"use client";
import { useState } from "react";
import { AppShell } from "../layout/AppShell";
import { AnalysisSummary } from "../analysis/AnalysisSummary";
import { VerdictBadge } from "../analysis/VerdictBadge";
import { ReviewActions } from "../hitl/ReviewActions";
import { ReviewHistory } from "../hitl/ReviewHistory";
import { ActionAuthorization } from "../hitl/ActionAuthorization";
import { ErrorNotice, Loading } from "../ui/Feedback";
import { useResource } from "../../hooks/useResource";
import { casePath } from "../../lib/api";
import type { Case } from "../../lib/types";
import { defangText } from "../../utils/defang";
import { formatDate } from "../../utils/format";

export function CaseWorkspace({ caseId }: { caseId: string }) {
  const validId = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(caseId);
  const { data, error, loading, reload } = useResource<Case>(validId ? casePath(caseId) : null);
  const [version, setVersion] = useState(0);
  async function changed() { await reload(); setVersion(value => value + 1); }
  return <AppShell title="Chi tiết case"><div className="stack">
    {!validId ? <div role="alert" className="notice error">422 · Case ID không hợp lệ.</div> : <>
      <button className="refresh" disabled={loading} onClick={() => void changed()}>Tải lại case</button>
      <ErrorNotice error={error} />{loading && <Loading />}
      {data && <><section className="panel"><p className="eyebrow">CASE <span className="mono">{data.case_id}</span></p><h2>{defangText(data.original_filename)}</h2>
        <p>Created: {formatDate(data.created_at)} · Updated: {formatDate(data.updated_at)}</p></section>
        <AnalysisSummary analysis={data.ai_assessment} />
        <section className="panel" aria-label="Human review"><h2>Human review</h2><p>Review status: <VerdictBadge verdict={data.review_status} /></p>
          <dl><dt>Reviewer</dt><dd className="mono">{data.reviewer_id ?? "—"}</dd><dt>Reviewed at</dt><dd>{formatDate(data.reviewed_at)}</dd>
            <dt>Reason</dt><dd>{defangText(data.review_reason ?? "—")}</dd></dl>
          {data.analyst_assessment ? <div className="human-result"><h3>Analyst assessment</h3><VerdictBadge verdict={data.analyst_assessment.label} /><p>{defangText(data.analyst_assessment.summary)}</p>
            <p>Allowed action kinds: {data.allowed_actions.join(", ") || "Không có"}</p></div> : <p className="muted">Chưa có analyst override; AI snapshot ở phía trên được giữ nguyên.</p>}
          <ReviewActions caseData={data} onChanged={changed} />
        </section><ActionAuthorization caseData={data} onChanged={changed} />
        <ReviewHistory key={`${caseId}:${version}`} caseId={caseId} />
      </>}
    </>}
  </div></AppShell>;
}
