"use client";
import { useAuth } from "../../hooks/useAuth";
import { useRouter } from "next/navigation";
export function Header({ title }: { title: string }) {
  const { user, logout } = useAuth();
  const router = useRouter();
  return (
    <header className="topbar">
      <h1>{title}</h1>
      <div className="session-info"><span>{user?.email} <small>{user?.role}</small></span>
        <button onClick={() => { logout(); router.replace("/login"); }}>Đăng xuất</button></div>
    </header>
  );
}
