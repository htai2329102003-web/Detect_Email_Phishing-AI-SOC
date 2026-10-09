"use client";
import { useState } from "react";
import { api } from "../lib/api";
import type { AnalysisResponse } from "../lib/types";
export function useAnalysis() {
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [isLoading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  async function analyze(file: File) {
    setLoading(true); setError(null); setAnalysis(null);
    try { setAnalysis(await api.analyze(file)); }
    catch (cause) { setError(cause instanceof Error ? cause : new Error("Không phân tích được email.")); }
    finally { setLoading(false); }
  }
  function reset() { setAnalysis(null); setError(null); }
  return { analysis, isLoading, error, analyze, reset };
}
