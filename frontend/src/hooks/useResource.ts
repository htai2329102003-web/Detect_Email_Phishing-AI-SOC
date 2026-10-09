"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "./useAuth";
import { apiRequest } from "../lib/api";

export function useResource<T>(path: string | null) {
  const { user } = useAuth();
  const userId = user?.user_id;
  const key = `${userId ?? ""}:${path ?? ""}`;
  type Resource = { key: string; data: T | null; error: Error | null; loading: boolean };
  const [state, setState] = useState<Resource>({ key: "", data: null, error: null, loading: true });
  const controller = useRef<AbortController | null>(null);
  const load = useCallback((): Promise<void> => {
    controller.current?.abort();
    if (!path || !userId) return Promise.resolve();
    const current = new AbortController(); controller.current = current;
    return apiRequest<T>(path, { signal: current.signal }).then(value => {
      if (!current.signal.aborted) setState({ key, data: value, error: null, loading: false });
    }).catch(cause => {
      if (!current.signal.aborted) setState({ key, data: null, loading: false,
        error: cause instanceof Error ? cause : new Error("Không tải được dữ liệu.") });
    });
  }, [key, path, userId]);
  const reload = useCallback(async () => {
    setState({ key, data: null, error: null, loading: true });
    await load();
  }, [key, load]);
  useEffect(() => { void load(); return () => controller.current?.abort(); }, [load]);
  // Changing resource/identity immediately hides old data without a synchronous effect update.
  const current = state.key === key ? state : { data: null, error: null, loading: !!path && !!userId };
  return { data: current.data, error: current.error, loading: current.loading, reload };
}
