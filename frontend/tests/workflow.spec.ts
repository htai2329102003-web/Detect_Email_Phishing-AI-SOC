import { expect, test, type Page } from "@playwright/test";
import { resolve } from "node:path";

const fixtures = resolve(process.cwd(), "../tests/fixtures/emails");
const artifacts = resolve(process.cwd(), "../docs/examples");
const password = process.env.SMOKE_USER_PASSWORD;
if (!password) throw new Error("Run through scripts.smoke_group6; no default credentials exist");

async function login(page: Page, role: "analyst" | "admin" = "analyst") {
  await page.goto("/login");
  await page.getByLabel("Email", { exact: true }).fill(`${role}@recipient.test`);
  await page.getByLabel("Mật khẩu", { exact: true }).fill(password!);
  await page.getByRole("button", { name: "Đăng nhập", exact: true }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole("heading", { name: "Case gần đây" })).toBeVisible();
}
async function upload(page: Page, filename = "clean.eml", expected = "0/100") {
  await page.goto("/analyze");
  await page.getByLabel("Email file (.eml)").setInputFiles(resolve(fixtures, filename));
  await page.getByRole("button", { name: "Phân tích", exact: true }).click();
  await expect(page.getByTestId("risk-score")).toHaveText(expected);
  await page.getByRole("link", { name: "Mở case", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Human review", exact: true })).toBeVisible();
  await expect(page.getByTestId("risk-score")).toHaveText(expected);
}
async function reviewStatus(page: Page, status: string) {
  await expect(page.getByRole("region", { name: "Human review" }).getByLabel(`Verdict: ${status}`, { exact: true })).toBeVisible();
}

test("Analyst login → clean upload → APPROVE → refresh → authorize → audit", async ({ page }) => {
  await login(page);
  await expect(page.getByRole("link", { name: "Admin", exact: true })).toHaveCount(0);
  await upload(page);
  await reviewStatus(page, "PENDING");
  await page.getByRole("button", { name: "Đề xuất action" }).click();
  await expect(page.getByRole("button", { name: "Authorize QUARANTINE" })).toBeDisabled();
  await page.getByRole("button", { name: "Xác nhận review" }).click();
  await reviewStatus(page, "APPROVED");
  await page.reload();
  await reviewStatus(page, "APPROVED");
  await expect(page.getByTestId("risk-score")).toHaveText("0/100");
  await page.getByLabel("Authorization reason").fill("Explicit analyst authorization from browser smoke");
  await page.getByRole("button", { name: "Authorize QUARANTINE" }).click();
  await expect(page.getByText("AUTHORIZED", { exact: true })).toBeVisible();
  await expect(page.getByText("ACTION_AUTHORIZED", { exact: true })).toBeVisible();
  await expect(page.getByText("REVIEW_APPROVED", { exact: true })).toBeVisible();
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Case gần đây" })).toBeVisible();
  await page.screenshot({ path: resolve(artifacts, "group6-dashboard.png"), fullPage: true });
  await page.getByRole("button", { name: "Đăng xuất" }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect(await page.evaluate(() => sessionStorage.getItem("phishhunter.session"))).toBeNull();
  await page.goto("/cases");
  await expect(page).toHaveURL(/\/login$/);
});

test("REJECT persists, stale-tab review returns 409 and action cannot authorize", async ({ page, context }) => {
  await login(page); await upload(page);
  const stale = await context.newPage(); await login(stale); await stale.goto(page.url());
  await reviewStatus(stale, "PENDING");
  await page.getByRole("radio", { name: "REJECT", exact: true }).check();
  await page.getByRole("button", { name: "Xác nhận review" }).click();
  await reviewStatus(page, "REJECTED"); await page.reload(); await reviewStatus(page, "REJECTED");
  await page.getByRole("button", { name: "Đề xuất action" }).click();
  await expect(page.getByRole("button", { name: "Authorize QUARANTINE" })).toBeDisabled();
  await expect(page.getByText("REVIEW_REJECTED", { exact: true })).toBeVisible();
  await stale.getByRole("button", { name: "Xác nhận review" }).click();
  await expect(stale.locator(".notice.error")).toContainText("HTTP 409");
  await stale.getByRole("button", { name: "Tải lại case" }).click();
  await reviewStatus(stale, "REJECTED"); await stale.close();
});

test("MODIFY keeps AI score/label, separates analyst result and escapes/defangs text", async ({ page }) => {
  await login(page); await upload(page, "href_mismatch.eml", "60/100");
  await expect(page.getByText("hxxps://other[.]test/login", { exact: false }).first()).toBeVisible();
  await expect(page.locator('a[href^="http:"] , a[href^="https:"]')).toHaveCount(0);
  await page.getByRole("radio", { name: "MODIFY", exact: true }).check();
  await expect(page.getByRole("button", { name: "Xác nhận review" })).toBeDisabled();
  await page.getByLabel("Reason (bắt buộc)").fill("Manual interpretation after evidence review");
  await page.getByLabel("Analyst label").selectOption("SAFE");
  await page.getByLabel("Analyst summary").fill('<img src=x onerror="window.phishPwned=true"> https://evil.test/login');
  await page.getByRole("checkbox", { name: "QUARANTINE", exact: true }).check();
  await page.getByRole("button", { name: "Xác nhận review" }).click();
  await reviewStatus(page, "MODIFIED"); await page.reload(); await reviewStatus(page, "MODIFIED");
  await expect(page.getByTestId("risk-score")).toHaveText("60/100");
  await expect(page.getByRole("region", { name: "AI assessment" }).getByLabel("Verdict: NEEDS_ANALYST_REVIEW", { exact: true }).first()).toBeVisible();
  const human = page.getByRole("region", { name: "Human review" });
  await expect(human.getByLabel("Verdict: SAFE", { exact: true })).toBeVisible();
  await expect(human.getByText('hxxps://evil[.]test/login', { exact: false })).toBeVisible();
  await expect(page.locator("main img")).toHaveCount(0);
  expect(await page.evaluate(() => (window as Window & { phishPwned?: boolean }).phishPwned)).toBeUndefined();
  await expect(page.getByText("REVIEW_MODIFIED", { exact: true })).toBeVisible();
  await page.screenshot({ path: resolve(artifacts, "group6-case-review.png"), fullPage: true });
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { name: "Case gần đây" })).toBeVisible();
  await page.screenshot({ path: resolve(artifacts, "group6-dashboard.png"), fullPage: true });
});

test("401, role UX, wrong/large file and real malformed upload 422", async ({ page }) => {
  await page.goto("/analyze"); await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("Email", { exact: true }).fill("analyst@recipient.test");
  await page.getByLabel("Mật khẩu", { exact: true }).fill("wrong");
  await page.getByRole("button", { name: "Đăng nhập", exact: true }).click();
  await expect(page.locator(".notice.error")).toContainText("HTTP 401");
  await login(page);
  await page.goto("/admin"); await expect(page.locator(".notice.error")).toContainText("403");
  await page.goto("/analyze");
  const input = page.getByLabel("Email file (.eml)");
  await input.setInputFiles({ name: "wrong.txt", mimeType: "text/plain", buffer: Buffer.from("inert") });
  await expect(page.locator(".notice.error")).toContainText(".eml");
  await expect(page.getByRole("button", { name: "Phân tích", exact: true })).toBeDisabled();
  await input.setInputFiles({ name: "large.eml", mimeType: "message/rfc822", buffer: Buffer.alloc(5 * 1024 * 1024 + 1) });
  await expect(page.locator(".notice.error")).toContainText("5 MiB");
  await input.setInputFiles(resolve(fixtures, "malformed.eml"));
  await page.getByRole("button", { name: "Phân tích", exact: true }).click();
  await expect(page.locator(".notice.error")).toContainText("HTTP 422");
  await page.goto("/cases/00000000-0000-0000-0000-000000000000");
  await expect(page.locator(".notice.error")).toContainText("HTTP 404");
});

test("Admin area uses real user create/update and system audit APIs", async ({ page }) => {
  await login(page, "admin");
  await page.getByRole("link", { name: "Admin", exact: true }).click();
  await expect(page.getByRole("heading", { name: "System audit" })).toBeVisible();
  await page.getByRole("link", { name: "Quản lý users" }).click();
  await page.getByLabel("Email user").fill("browser-created@recipient.test");
  await page.getByLabel("Mật khẩu mới").fill(password!);
  await page.getByRole("button", { name: "Tạo user", exact: true }).click();
  await expect(page.getByText("Đã tạo user.", { exact: true })).toBeVisible();
  const row = page.getByRole("row").filter({ hasText: "browser-created@recipient[.]test" });
  await expect(row).toBeVisible();
  await row.getByRole("combobox").selectOption("ADMIN");
  await row.getByRole("button", { name: "Lưu user" }).click();
  await expect(page.getByRole("row").filter({ hasText: "browser-created@recipient[.]test" }).getByRole("combobox")).toHaveValue("ADMIN");
});
