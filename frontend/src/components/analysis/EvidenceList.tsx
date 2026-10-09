import type { Evidence } from "../../lib/types";
import { defangIndicator, defangText, safeJson } from "../../utils/defang";
import { formatDate } from "../../utils/format";

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (evidence.length === 0) return <p className="muted">Chưa có evidence qua Gate 1.</p>;

  return (
    <div className="evidence-list">
      {evidence.map((item) => (
        <details key={item.evidence_id} id={item.evidence_id}>
          <summary><span className={`check-result ${item.result.toLowerCase()}`}>{item.result}</span> {item.signal_type}
            <span className="muted"> · {item.family} · {item.severity}</span></summary>
          <p className="indicator">{defangIndicator(item.indicator)}</p>
          <dl><dt>Evidence ID</dt><dd className="mono">{item.evidence_id}</dd><dt>Analyzer / tool</dt><dd>{defangText(`${item.analyzer} / ${item.tool}`)}</dd>
            <dt>Tool status / confidence</dt><dd>{item.tool_status} / {item.confidence}</dd>
            <dt>Provenance</dt><dd>{item.provenance.source}: {defangText(item.provenance.reference)}</dd>
            <dt>Collected</dt><dd>{formatDate(item.collected_at)}</dd></dl>
          <pre>{safeJson(item.value)}</pre>
        </details>
      ))}
    </div>
  );
}
