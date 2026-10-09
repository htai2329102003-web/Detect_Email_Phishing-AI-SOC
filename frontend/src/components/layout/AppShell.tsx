"use client";
import type { ReactNode } from "react";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../hooks/useAuth";
import { Loading } from "../ui/Feedback";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";

export function AppShell({ title, children, admin = false }: { title: string; children: ReactNode; admin?: boolean }) {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  useEffect(() => { if (!isLoading && !user) router.replace("/login"); }, [isLoading, user, router]);
  if (isLoading || !user) return <main className="auth-screen"><Loading text="Đang kiểm tra phiên đăng nhập…" /></main>;
  return (
    <div className="app-shell">
      <Sidebar />
      <section className="workspace">
        <Header title={title} />
        <main>{admin && user.role !== "ADMIN" ? <div role="alert" className="notice error">403 · Khu vực này chỉ dành cho Admin.</div> : children}</main>
      </section>
    </div>
  );
}
