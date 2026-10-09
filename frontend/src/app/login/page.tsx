"use client";
import { useEffect, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../hooks/useAuth";
import { ErrorNotice } from "../../components/ui/Feedback";
export default function LoginPage() {
  const auth = useAuth(); const router = useRouter();
  const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<Error | null>(null);
  useEffect(() => { if (auth.user) router.replace("/dashboard"); }, [auth.user, router]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(null);
    try { await auth.login(email.trim(), password); setPassword(""); router.replace("/dashboard"); }
    catch (cause) { setPassword(""); setError(cause instanceof Error ? cause : new Error("Đăng nhập thất bại.")); }
    finally { setBusy(false); }
  }
  return <main className="auth-screen"><section className="login-card panel">
    <p className="eyebrow">PHISHHUNTER / SOC WORKSPACE</p><h1>Đăng nhập</h1>
    <p className="muted">Phân tích bằng chứng. Analyst quyết định bước xử lý.</p>
    <ErrorNotice error={error ?? auth.error} />
    <form onSubmit={submit}><label>Email<input type="email" autoComplete="username" maxLength={320} required value={email} onChange={e => setEmail(e.target.value)} /></label>
      <label>Mật khẩu<input type="password" autoComplete="current-password" maxLength={256} required value={password} onChange={e => setPassword(e.target.value)} /></label>
      <button className="primary" disabled={busy || auth.isLoading}>{busy ? "Đang đăng nhập…" : "Đăng nhập"}</button>
    </form></section></main>;
}
