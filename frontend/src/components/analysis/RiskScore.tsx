import { formatRiskScore } from "../../utils/format";
export function RiskScore({ score }: { score: number | null }) {
  return <div className="score"><span className="muted">AI risk score</span><strong data-testid="risk-score">{formatRiskScore(score)}</strong></div>;
}
