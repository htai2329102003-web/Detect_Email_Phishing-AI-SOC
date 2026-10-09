"use client";
import { useState } from "react";
import { AppShell } from "../../components/layout/AppShell";
import { CaseTable } from "../../components/cases/CaseTable";
import { ErrorNotice, Loading, Pager } from "../../components/ui/Feedback";
import { useResource } from "../../hooks/useResource";
import type { CaseSummary } from "../../lib/types";

export default function CasesPage() {
  const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useResource<CaseSummary[]>(`/cases?limit=20&offset=${offset}`);
  return (
    <AppShell title="Danh sách case">
      <section className="panel"><div className="section-heading"><h2>SOC case queue</h2><button disabled={loading} onClick={() => void reload()}>Tải lại</button></div>
        <ErrorNotice error={error} />{loading ? <Loading /> : data && <><CaseTable cases={data} /><Pager offset={offset} size={20} count={data.length} onChange={setOffset} /></>}
      </section>
    </AppShell>
  );
}
