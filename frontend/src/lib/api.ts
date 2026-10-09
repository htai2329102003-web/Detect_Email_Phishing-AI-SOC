import { clearSession, readSession } from "./auth";
import type { AnalysisResponse, AuthUser, Case, CaseAction, CaseSummary, LoginResponse, ReviewRequest, UserCreate, ActionKind, Role } from "./types";

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1").replace(/\/$/, "");
export class ApiError extends Error {
  constructor(public status: number, public code?: string, login = false) {
    const messages: Record<number, string> = {
      0: "Không kết nối được dịch vụ. Kiểm tra mạng và địa chỉ backend.",
      401: login ? "Email hoặc mật khẩu không đúng." : "Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.",
      403: "Bạn không có quyền thực hiện thao tác này.",
      404: "Không tìm thấy dữ liệu được yêu cầu.",
      409: "Trạng thái đã thay đổi hoặc thao tác không được phép. Hãy tải lại dữ liệu trước khi thử lại.",
      413: "File quá lớn. Giới hạn là 5 MiB.",
      415: "Loại file không được hỗ trợ. Hãy chọn file .eml.",
      422: "Email hoặc dữ liệu gửi lên không hợp lệ. Kiểm tra định dạng và các trường bắt buộc.",
      503: "Dịch vụ chưa sẵn sàng. Hãy kiểm tra cấu hình và kết nối backend/database.",
    };
    super(messages[status] ?? "Dịch vụ gặp lỗi. Vui lòng thử lại sau.");
    this.name = "ApiError";
  }
}
type Options = RequestInit & { authenticated?: boolean };
export async function apiRequest<T>(path: string, options: Options = {}): Promise<T> {
  const { authenticated = true, ...init } = options;
  const headers = new Headers(init.headers);
  if (authenticated) {
    const token = readSession()?.token;
    if (!token) throw new ApiError(401);
    headers.set("Authorization", `Bearer ${token}`);
  }
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers, cache: "no-store", credentials: "omit" });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0);
  }
  if (!response.ok) {
    if (response.status === 401 && authenticated) clearSession();
    let code: string | undefined;
    try {
      const body: unknown = await response.json();
      if (body && typeof body === "object" && "detail" in body && body.detail &&
          typeof body.detail === "object" && "code" in body.detail && typeof body.detail.code === "string") code = body.detail.code;
    } catch { /* Keep HTTP status for a non-JSON gateway response. */ }
    throw new ApiError(response.status, code, !authenticated);
  }
  try { return await response.json() as T; } catch { throw new ApiError(500); }
}
function json(body: unknown): RequestInit {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}
export const casePath = (id: string) => `/cases/${encodeURIComponent(id)}`;
export const api = {
  login: (email: string, password: string) => apiRequest<LoginResponse>("/auth/login", { ...json({ email, password }), authenticated: false }),
  me: () => apiRequest<AuthUser>("/auth/me"),
  analyze: (file: File) => {
    const body = new FormData(); body.append("file", file);
    return apiRequest<AnalysisResponse>("/analysis", { method: "POST", body });
  },
  cases: (offset = 0, limit = 20, signal?: AbortSignal) => apiRequest<CaseSummary[]>(`/cases?limit=${limit}&offset=${offset}`, { signal }),
  review: (id: string, body: ReviewRequest) => apiRequest<Case>(`${casePath(id)}/review`, json(body)),
  propose: (id: string, kind: ActionKind) => apiRequest<CaseAction>(`${casePath(id)}/actions`, json({ kind })),
  authorize: (id: string, actionId: string, reason: string) => apiRequest<CaseAction>(`${casePath(id)}/actions/${encodeURIComponent(actionId)}/authorize`, json({ reason })),
  createUser: (body: UserCreate) => apiRequest<AuthUser>("/admin/users", json(body)),
  updateUser: (id: string, body: { role?: Role; active?: boolean }) => apiRequest<AuthUser>(`/admin/users/${encodeURIComponent(id)}`, { ...json(body), method: "PATCH" }),
};
export async function dashboardCases(signal: AbortSignal) {
  const cases = new Map<string, CaseSummary>();
  // No aggregate endpoint: bounded pagination, with explicit partial reporting.
  for (let page = 0; page < 50; page++) {
    const batch = await api.cases(page * 100, 100, signal);
    batch.forEach(item => cases.set(item.case_id, item));
    if (batch.length < 100) return { cases: [...cases.values()], complete: true };
  }
  return { cases: [...cases.values()], complete: false };
}
