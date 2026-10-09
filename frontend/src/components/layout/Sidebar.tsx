"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "../../hooks/useAuth";

const navigation = [
  ["Dashboard", "/dashboard"],
  ["Analyze", "/analyze"],
  ["Cases", "/cases"],
];

export function Sidebar() {
  const { user } = useAuth();
  const path = usePathname();
  const links = user?.role === "ADMIN" ? [...navigation, ["Admin", "/admin"]] : navigation;
  return (
    <aside aria-label="Primary navigation">
      <Link href="/dashboard" className="brand">◈ PhishHunter</Link><p className="muted">SOC · Evidence &amp; Review</p>
      <nav>
        {links.map(([label, href]) => (
          <Link key={href} href={href} aria-current={path === href ? "page" : undefined}>{label}</Link>
        ))}
      </nav>
      <p className="sidebar-note">Evidence trước quyết định.<br />Mọi action cần human authorization.</p>
    </aside>
  );
}
