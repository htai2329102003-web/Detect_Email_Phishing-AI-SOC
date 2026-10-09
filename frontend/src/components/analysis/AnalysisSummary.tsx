import { EvidenceList } from "./EvidenceList";
import { RiskScore } from "./RiskScore";
import { VerdictBadge } from "./VerdictBadge";
import type { AnalysisResponse } from "../../lib/types";
import { defangIndicator, defangText } from "../../utils/defang";

export function AnalysisSummary({ analysis }: { analysis: AnalysisResponse }) {
  return (
    <section className="stack" aria-label="AI assessment">
      <section className="panel"><h2>AI assessment</h2>
        <div className="result-overview"><RiskScore score={analysis.score} /><div>
          <p>Label candidate <VerdictBadge verdict={analysis.label_candidate} /></p>
          <p>Assessment label <VerdictBadge verdict={analysis.assessment_label} /></p>
          <p>Analysis scope: <code>{analysis.analysis_scope}</code></p>
          <p>Requires review: <strong>{String(analysis.requires_review)}</strong> <span className="muted">(AI snapshot)</span></p>
        </div></div>
        <p>{defangText(analysis.analyst_summary)}</p>
        <p>Gate 2: <strong>{analysis.claim_validation_status}</strong> · Verdict attempts: {analysis.verdict_attempts}</p>
        {analysis.trust_warnings.length > 0 && <p className="notice warning">Trust warnings: {analysis.trust_warnings.join(", ")}</p>}
        {analysis.guardrail_signals.length > 0 && <p className="notice warning">Guardrail signals: {analysis.guardrail_signals.join(", ")}</p>}
      </section>
      <section className="panel"><h2>Coverage</h2><p>{analysis.coverage.complete ? "Đủ coverage trong scope" : "Coverage chưa đủ"} · Ratio: {analysis.coverage.ratio}</p>
        <dl>{(["required", "applicable", "completed", "missing", "unknown"] as const).map(key => <div key={key}><dt>{key}</dt><dd>{analysis.coverage[key].join(", ") || "—"}</dd></div>)}</dl>
        <p>Analyzer runs: {analysis.analyzer_runs.map(run => `${run.analyzer}: ${run.status}`).join(" · ")}</p>
        {analysis.reasons.length > 0 && <p>Reasons: {analysis.reasons.join(", ")}</p>}
      </section>
      <section className="panel"><h2>Claims</h2>{analysis.claims.length === 0 ? <p className="muted">Chưa có grounded claim.</p> : <ul className="claim-list">
        {analysis.claims.map((claim, index) => <li key={index}><strong>{claim.claim_type}</strong> — {defangText(claim.text)}
          <div className="mono small">Evidence IDs: {claim.evidence_ids.join(", ")}</div>
          {claim.indicators.map((item, i) => <div className="indicator small" key={i}>{item.path}: {defangIndicator(item.value)}</div>)}
        </li>)}</ul>}
      </section>
      <section className="panel"><h2>Evidence · Gate 1</h2><p className="muted">Indicators được defang, không mở URL hoặc render attachment.</p><EvidenceList evidence={analysis.evidence} /></section>
      <section className="panel"><h2>Risk contributions</h2>{analysis.contributions.length === 0 ? <p>Không có contribution.</p> : <div className="table-scroll"><table><thead><tr><th>Signal / evidence</th><th>Family</th><th>Strength</th><th>Applied strength</th></tr></thead><tbody>
        {analysis.contributions.map(item => <tr key={item.evidence_id}><td>{item.signal_type}<small className="mono">{item.evidence_id}</small></td><td>{item.family}</td><td>{item.strength}</td><td>{item.applied_strength}</td></tr>)}
      </tbody></table></div>}</section>
      <section className="panel"><h2>Recommended actions</h2><ul>{analysis.recommended_actions.map(action => <li key={action}>{action}</li>)}</ul>
        <p className="muted">Khuyến nghị của AI. Human review và action authorization là các bước riêng.</p></section>
    </section>
  );
}
