"use client";
import { useState, type FormEvent } from "react";
import { AppShell } from "../../../components/layout/AppShell";
import { useResource } from "../../../hooks/useResource";
import { useAuth } from "../../../hooks/useAuth";
import { api } from "../../../lib/api";
import type { AuthUser, Role } from "../../../lib/types";
import { ErrorNotice, Loading, Pager } from "../../../components/ui/Feedback";
import { defangText } from "../../../utils/defang";
import { formatDate } from "../../../utils/format";

function UserRow({ user, own, reload }: { user: AuthUser; own: boolean; reload: () => Promise<void> }) {
  const [role, setRole] = useState(user.role); const [active, setActive] = useState(user.active);
  const [busy, setBusy] = useState(false); const [error, setError] = useState<Error | null>(null);
  async function update() {
    setBusy(true); setError(null);
    try { await api.updateUser(user.user_id, { role, active }); await reload(); }
    catch (cause) { setError(cause instanceof Error ? cause : new Error("Không cập nhật được user.")); }
    finally { setBusy(false); }
  }
  return <tr><td>{defangText(user.email)}{own && <small>Tài khoản của bạn</small>}<small className="mono">{user.user_id}</small></td><td>
    <select aria-label={`Role ${user.email}`} disabled={busy || own} value={role} onChange={e => setRole(e.target.value as Role)}><option>SOC_ANALYST</option><option>ADMIN</option></select></td>
    <td><label className="choice"><input type="checkbox" disabled={busy || own} checked={active} onChange={e => setActive(e.target.checked)} />Active</label></td>
    <td>{formatDate(user.created_at)}</td><td><button disabled={busy || own || (role === user.role && active === user.active)} onClick={() => void update()}>Lưu user</button><ErrorNotice error={error} /></td></tr>;
}

export default function AdminUsersPage() {
  const { user } = useAuth(); const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useResource<AuthUser[]>(user?.role === "ADMIN" ? `/admin/users?limit=20&offset=${offset}` : null);
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [role, setRole] = useState<Role>("SOC_ANALYST");
  const [busy, setBusy] = useState(false); const [formError, setFormError] = useState<Error | null>(null); const [success, setSuccess] = useState(false);
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setFormError(null); setSuccess(false);
    try { await api.createUser({ email: email.trim(), password, role }); setEmail(""); setSuccess(true); if (offset === 0) await reload(); else setOffset(0); }
    catch (cause) { setFormError(cause instanceof Error ? cause : new Error("Không tạo được user.")); }
    finally { setPassword(""); setBusy(false); }
  }
  return (
    <AppShell title="User management" admin><div className="stack">
      <section className="panel"><h2>Tạo user</h2><form onSubmit={create}><fieldset disabled={busy}>
        <label>Email user<input type="email" autoComplete="off" maxLength={320} required value={email} onChange={e => setEmail(e.target.value)} /></label>
        <label>Mật khẩu mới<input type="password" autoComplete="new-password" required minLength={12} maxLength={256} value={password} onChange={e => setPassword(e.target.value)} /></label>
        <label>Role<select value={role} onChange={e => setRole(e.target.value as Role)}><option>SOC_ANALYST</option><option>ADMIN</option></select></label>
        <ErrorNotice error={formError} />{success && <p role="status" className="notice success">Đã tạo user.</p>}<button className="primary" disabled={busy}>{busy ? "Đang tạo…" : "Tạo user"}</button>
      </fieldset></form></section>
      <section className="panel"><div className="section-heading"><h2>Users</h2><button disabled={loading} onClick={() => void reload()}>Tải lại</button></div><ErrorNotice error={error} />
        {loading ? <Loading /> : data && <>{!data.length ? <p className="empty">Không có user trên trang này.</p> : <div className="table-scroll"><table><thead><tr><th>User</th><th>Role</th><th>Active</th><th>Created</th><th>Update</th></tr></thead><tbody>
          {data.map(item => <UserRow key={item.user_id} user={item} own={item.user_id === user?.user_id} reload={reload} />)}
        </tbody></table></div>}<Pager offset={offset} size={20} count={data.length} onChange={setOffset} /></>}
      </section></div>
    </AppShell>
  );
}
