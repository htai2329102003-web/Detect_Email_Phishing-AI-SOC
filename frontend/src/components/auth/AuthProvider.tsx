"use client";
import { useEffect, useState, type ReactNode } from "react";
import { AuthContext } from "../../hooks/useAuth";
import { api } from "../../lib/api";
import { AUTH_CHANGED, clearSession, readSession, saveSession } from "../../lib/auth";
import type { AuthUser } from "../../lib/types";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  useEffect(() => {
    let active = true;
    const signedOut = () => { setUser(null); };
    window.addEventListener(AUTH_CHANGED, signedOut);
    async function restore() {
      try {
        if (readSession()) {
          const current = await api.me();
          if (active) setUser(current);
        }
      } catch (cause) {
        clearSession();
        if (active) setError(cause instanceof Error ? cause : new Error("Không xác minh được phiên."));
      } finally { if (active) setLoading(false); }
    }
    void restore();
    return () => { active = false; window.removeEventListener(AUTH_CHANGED, signedOut); };
  }, []);
  useEffect(() => {
    if (!user) return;
    const session = readSession();
    if (!session) return;
    const timer = window.setTimeout(clearSession, Math.max(0, session.expiresAt - Date.now()));
    return () => window.clearTimeout(timer);
  }, [user]);
  async function login(email: string, password: string) {
    setError(null);
    try {
      const result = await api.login(email, password);
      saveSession(result);
      setUser(await api.me());
    } catch (cause) { clearSession(); throw cause; }
  }
  function logout() { clearSession(); setError(null); }
  return <AuthContext.Provider value={{ user, isLoading, error, login, logout }}>{children}</AuthContext.Provider>;
}
