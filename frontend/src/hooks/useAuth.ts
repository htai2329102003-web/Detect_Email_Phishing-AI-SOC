"use client";
import { createContext, useContext } from "react";
import type { AuthUser } from "../lib/types";
export type AuthState = {
  user: AuthUser | null; isLoading: boolean; error: Error | null;
  login: (email: string, password: string) => Promise<void>; logout: () => void;
};
export const AuthContext = createContext<AuthState | null>(null);
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("AuthProvider is required");
  return { ...context, isAuthenticated: context.user !== null };
}
