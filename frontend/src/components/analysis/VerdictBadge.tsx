export function VerdictBadge({ verdict }: { verdict: string }) {
  const tone = ({ SAFE: "safe", SUSPICIOUS: "warning", PHISHING: "danger", NEEDS_ANALYST_REVIEW: "review",
    PENDING: "review", APPROVED: "safe", REJECTED: "danger", MODIFIED: "warning" } as Record<string, string>)[verdict] ?? "neutral";
  return <span className={`badge ${tone}`} aria-label={`Verdict: ${verdict}`}>{verdict}</span>;
}
