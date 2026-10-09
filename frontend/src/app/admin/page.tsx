"use client";
import Link from "next/link";
import { useState } from "react";
import { AppShell } from "../../components/layout/AppShell";
import { AuditTable } from "../../components/hitl/ReviewHistory";
import { ErrorNotice, Loading, Pager } from "../../components/ui/Feedback";
import { useResource } from "../../hooks/useResource";
import { useAuth } from "../../hooks/useAuth";
import type { AuditEntry } from "../../lib/types";

export default function AdminPage() {
  const { user } = useAuth(); const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useResource<AuditEntry[]>(user?.role === "ADMIN" ? `/admin/audit?limit=50&offset=${offset}` : null);
  return (
    <AppShell title="Administration" admin>
      <section className="panel"><div className="section-heading"><h2>System audit</h2><Link href="/admin/users">Quản lý users</Link><button disabled={loading} onClick={() => void reload()}>Tải lại</button></div>
        <ErrorNotice error={error} />{loading ? <Loading /> : data && <><AuditTable entries={data} /><Pager offset={offset} size={50} count={data.length} onChange={setOffset} /></>}
      </section>
    </AppShell>
  );
}
