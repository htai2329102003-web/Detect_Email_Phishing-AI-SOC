import { ApiError } from "../../lib/api";
export function ErrorNotice({ error }: { error: Error | null }) {
  if (!error) return null;
  return <div role="alert" className="notice error">{error instanceof ApiError ? (error.status ? `HTTP ${error.status} · ` : "Network · ") : ""}{error.message}</div>;
}
export function Loading({ text = "Đang tải dữ liệu…" }: { text?: string }) {
  return <p role="status" className="muted">{text}</p>;
}
export function Pager({ offset, size, count, onChange }: { offset: number; size: number; count: number; onChange: (offset: number) => void }) {
  return <div className="pager"><button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - size))}>Trang trước</button>
    <span>Trang {Math.floor(offset / size) + 1}</span><button disabled={count < size} onClick={() => onChange(offset + size)}>Trang sau</button></div>;
}
