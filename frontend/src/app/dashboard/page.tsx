"use client";
import { useEffect, useState } from "react";
import { AppShell } from "../../components/layout/AppShell";
import { useAuth } from "../../hooks/useAuth";
import { dashboardCases } from "../../lib/api";
import type { CaseSummary, ReviewStatus } from "../../lib/types";
import { CaseTable } from "../../components/cases/CaseTable";
import { ErrorNotice, Loading } from "../../components/ui/Feedback";

export default function DashboardPage() {
  const { user } = useAuth(); const userId = user?.user_id;
  const [data, setData] = useState<{ cases: CaseSummary[]; complete: boolean } | null>(null);
  const [error, setError] = useState<Error | null>(null); const [version, setVersion] = useState(0);
  useEffect(() => {
    if (!userId) return;
    const controller = new AbortController();
    dashboardCases(controller.signal).then(result => { if (!controller.signal.aborted) setData(result); })
      .catch(cause => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause : new Error("Không tải được dashboard.")); });
    return () => controller.abort();
  }, [userId, version]);
  const statuses: ReviewStatus[] = ["PENDING", "APPROVED", "REJECTED", "MODIFIED"];
  return (
    <AppShell title="Dashboard">
      <div className="section-heading"><p className="muted">Dữ liệu từ case queue đang truy cập.</p><button onClick={() => { setData(null); setError(null); setVersion(v => v + 1); }}>Tải lại</button></div>
      <ErrorNotice error={error} />{!data && !error && <Loading />}
      {data && <><div className="stats"><div className="stat"><span>{data.complete ? "Tổng case" : "Case đã tải"}</span><strong>{data.cases.length}</strong></div>
        {statuses.map(status => <div className="stat" key={status}><span>{status}</span><strong>{data.cases.filter(item => item.review_status === status).length}</strong></div>)}
      </div>{!data.complete && <p className="notice warning">Đã tải tối đa 5.000 case; các số trên chỉ tính phần đã tải.</p>}
      <section className="panel"><h2>Case gần đây</h2><CaseTable cases={data.cases.slice(0, 5)} /></section></>}
    </AppShell>
  );
}
