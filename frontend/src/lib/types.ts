export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type Role = "SOC_ANALYST" | "ADMIN";
export type RiskLabel = "SAFE" | "SUSPICIOUS" | "PHISHING" | "NEEDS_ANALYST_REVIEW";
export const RISK_LABELS: RiskLabel[] = ["SAFE", "SUSPICIOUS", "PHISHING", "NEEDS_ANALYST_REVIEW"];
export type ReviewStatus = "PENDING" | "APPROVED" | "REJECTED" | "MODIFIED";
export type ActionKind = "QUARANTINE" | "BLOCK_SENDER" | "DELETE_EMAIL";
export const ACTION_KINDS: ActionKind[] = ["QUARANTINE", "BLOCK_SENDER", "DELETE_EMAIL"];
export type AuthUser = { user_id: string; email: string; role: Role; active: boolean; created_at: string };
export type LoginResponse = { access_token: string; token_type: "bearer"; expires_in: number };
export type Evidence = {
  evidence_id: string; analyzer: string; tool: string; signal_type: string; family: string;
  indicator: string; value: JsonValue; result: "PASS" | "FAIL" | "UNKNOWN";
  tool_status: "OK" | "TIMEOUT" | "RATE_LIMITED" | "ERROR";
  severity: "info" | "low" | "medium" | "high" | "critical"; confidence: number;
  provenance: { source: "local" | "external" | "llm"; reference: string }; collected_at: string;
};
export type Claim = {
  claim_type: "AUTHENTICATION" | "IDENTITY" | "URL" | "ATTACHMENT" | "QR" | "IOC" | "CONTENT_BEC" | "UNCERTAINTY";
  text: string; evidence_ids: string[];
  indicators: { evidence_id: string; path: string; value: string }[];
};
export type RiskContribution = {
  evidence_id: string; signal_type: string; family: string; strength: number; applied_strength: number;
};
export type Coverage = {
  required: string[]; applicable: string[]; completed: string[]; missing: string[]; unknown: string[];
  ratio: number; complete: boolean;
};
export type AnalysisResponse = {
  case_id: string; status: string; review_status?: "PENDING";
  score: number; label_candidate: RiskLabel; assessment_label: RiskLabel;
  coverage: Coverage; evidence: Evidence[]; contributions: RiskContribution[];
  analysis_scope: "static_local" | "static_local_partial" | "static_enriched" | "static_enriched_partial";
  analyzer_runs: { analyzer: string; status: string }[]; reasons: string[];
  risk_score: number; risk_level: string; verdict: string; requires_review: boolean;
  claims: Claim[]; recommended_actions: ("REVIEW_EVIDENCE" | "VERIFY_SENDER_OUT_OF_BAND")[];
  analyst_summary: string; claim_validation_status: "PASS" | "FILTERED" | "REJECTED";
  trust_warnings: string[]; guardrail_signals: string[]; pii_redaction_counts: Record<string, number>;
  verdict_attempts: number;
};
export type CaseSummary = {
  case_id: string; original_filename: string; submitted_by: string; review_status: ReviewStatus;
  created_at: string; updated_at: string; risk_score: number; label_candidate: RiskLabel;
  assessment_label: RiskLabel; analysis_scope: AnalysisResponse["analysis_scope"];
  reviewer_id: string | null; reviewed_at: string | null;
};
export type AnalystAssessment = { label: RiskLabel; summary: string };
export type CaseAction = {
  action_id: string; case_id: string; kind: ActionKind; state: "PROPOSED" | "AUTHORIZED" | "EXECUTED";
  proposed_by: string; authorized_by: string | null; authorization_reason: string | null;
  created_at: string; authorized_at: string | null;
};
export type Case = CaseSummary & {
  ai_assessment: AnalysisResponse; analyst_assessment: AnalystAssessment | null;
  review_reason: string | null; allowed_actions: ActionKind[]; actions: CaseAction[];
};
export type ReviewRequest =
  | { decision: "APPROVE" | "REJECT"; reason?: string }
  | { decision: "MODIFY"; reason: string; analyst_assessment: AnalystAssessment; allowed_actions: ActionKind[] };
export type AuditEntry = {
  audit_id: string; case_id: string | null; actor_id: string; event: string;
  old_state: string | null; new_state: string | null; reason: string | null;
  timestamp: string; event_metadata: Record<string, JsonValue>;
};
export type UserCreate = { email: string; password: string; role: Role };
