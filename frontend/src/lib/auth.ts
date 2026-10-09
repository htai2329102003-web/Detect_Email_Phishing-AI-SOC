import type { LoginResponse } from "./types";
const STORAGE_KEY = "phishhunter.session";
export const AUTH_CHANGED = "phishhunter-auth-changed";
type Session = { token: string; expiresAt: number };
let memorySession: Session | null = null;

export function clearSession(): void {
  memorySession = null;
  try { sessionStorage.removeItem(STORAGE_KEY); } catch { /* Memory-only if storage is unavailable. */ }
  if (typeof window !== "undefined") window.dispatchEvent(new Event(AUTH_CHANGED));
}
export function saveSession(response: LoginResponse): void {
  memorySession = { token: response.access_token, expiresAt: Date.now() + response.expires_in * 1000 };
  try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(memorySession)); } catch { /* Memory-only session. */ }
}
export function readSession(): Session | null {
  if (typeof window === "undefined") return null;
  if (!memorySession) {
    try {
      const raw: unknown = JSON.parse(sessionStorage.getItem(STORAGE_KEY) ?? "null");
      if (raw && typeof raw === "object" && "token" in raw && "expiresAt" in raw &&
          typeof raw.token === "string" && typeof raw.expiresAt === "number") {
        memorySession = { token: raw.token, expiresAt: raw.expiresAt };
      }
    } catch { /* Corrupt storage is treated as signed out. */ }
  }
  if (memorySession && memorySession.expiresAt <= Date.now()) clearSession();
  return memorySession;
}
