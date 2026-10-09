export function formatRiskScore(score: number | null): string {
  return score === null ? "Pending" : `${score}/100`;
}

export function formatDate(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("vi-VN");
}
