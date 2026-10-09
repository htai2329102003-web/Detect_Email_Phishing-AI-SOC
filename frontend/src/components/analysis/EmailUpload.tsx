"use client";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { useAnalysis } from "../../hooks/useAnalysis";
import { ErrorNotice } from "../ui/Feedback";
import { AnalysisSummary } from "./AnalysisSummary";
import { defangText } from "../../utils/defang";

const MAX_BYTES = 5 * 1024 * 1024;
export function validateEmailFile(file: File): string | null {
  if (!file.name.toLowerCase().endsWith(".eml")) return "Chỉ chấp nhận file .eml (HTTP 415 nếu gửi lên backend).";
  if (file.size > MAX_BYTES) return "File quá lớn. Giới hạn là 5 MiB (HTTP 413).";
  if (file.size === 0) return "File email rỗng. Vui lòng chọn file .eml có nội dung.";
  return null;
}

export function EmailUpload() {
  const { analysis, isLoading, error, analyze, reset } = useAnalysis();
  const [file, setFile] = useState<File | null>(null); const [validation, setValidation] = useState<string | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!file || isLoading) return;
    const message = validateEmailFile(file); setValidation(message); if (!message) await analyze(file);
  }
  return <div className="stack"><section className="panel"><h2>Upload email</h2>
    <p className="muted">Chọn file .eml, tối đa 5 MiB. Analysis thành công sẽ tạo case PENDING.</p>
    <form onSubmit={submit}><label htmlFor="email-file">Email file (.eml)</label>
      <input id="email-file" type="file" accept=".eml,message/rfc822" disabled={isLoading} onChange={e => {
        const selected = e.target.files?.[0] ?? null; setFile(selected); reset(); setValidation(selected ? validateEmailFile(selected) : null);
      }} />
      {file && <p>Đã chọn: <strong>{defangText(file.name)}</strong> · {file.size.toLocaleString("vi-VN")} bytes</p>}
      {validation && <div role="alert" className="notice error">{validation}</div>}<ErrorNotice error={error} />
      <button className="primary" disabled={!file || !!validation || isLoading}>{isLoading ? "Đang phân tích…" : "Phân tích"}</button>
      {isLoading && <p role="status">Đang chạy analyzer và lưu case…</p>}
    </form></section>
    {analysis && <><div role="status" className="notice success">Đã lưu case PENDING. <Link href={`/cases/${encodeURIComponent(analysis.case_id)}`}>Mở case</Link></div>
      <AnalysisSummary analysis={analysis} /></>}
  </div>;
}
