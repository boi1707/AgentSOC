import { test, expect } from "@playwright/test";

test("language switches immediately, persists, and assistant stays read-only", async ({
  page,
}) => {
  await page.goto("/console");
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill("e2e-review-fixture-not-a-live-secret");
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "VI", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Tổng quan an ninh" }),
  ).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "vi");
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Tổng quan an ninh" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Trợ lý AI", exact: true }).click();
  await page
    .getByRole("button", { name: "Rà soát 24 giờ qua", exact: true })
    .click();
  await expect(page.getByRole("log").getByText(/Tìm thấy/)).toBeVisible();
  await expect(page.getByRole("log").getByRole("button")).toHaveCount(0);
  const source = "10.100.27.10";
  const target = "172.22.50.10";
  // Rendering fixture only; keep the shared test server empty for the pipeline test.
  // Real SQLite/provider/API grounding is exercised in test_assistant_grounding.py.
  let rendered: object | undefined;
  await page.route("**/api/v1/assistant/threads/*", async (route) => {
    if (route.request().method() === "GET" && rendered) {
      const response = await route.fetch();
      const body = await response.json();
      await route.fulfill({
        response,
        json: { ...body, messages: [...body.messages, rendered] },
      });
    } else {
      await route.continue();
    }
  });
  await page.route("**/api/v1/assistant/threads/*/messages", async (route) => {
    rendered = {
      id: "fixture-message",
      question: route.request().postDataJSON().message,
      status: "completed",
      answer: {
        language: "vi",
        summary: "Dữ kiện fixture kiểm thử UI",
        notice: "Fixture",
        model_status: "unavailable",
        interpretation: null,
        fallback: {
          origin: "stored_analysis",
          label: "Stored analysis / Evidence-based summary",
          text: "ICMP từ 10.100.27.10 đến 172.22.50.10; Wazuh 100101, level 7. Kết luận đã lưu benign, confidence 0.92, grounded=1. Không đề xuất chặn IP vì bằng chứng không xác lập tấn công.",
          truncated: false,
        },
        truncated: false,
        citations: [],
        analysis: [],
        facts: [
          {
            incident_id: "lab-icmp-ui",
            status: "pending",
            priority: "normal",
            wazuh_level: 7,
            verdict: "benign",
            confidence: 0.92,
            grounded: 1,
            missing_evidence: false,
            source_ips: [source],
            destination_ips: [target],
            rules: [
              {
                evidence_id: "lab-icmp-ui-evidence",
                rule_id: "100101",
                level: 7,
              },
            ],
            policy_explanation:
              "Không đề xuất chặn IP: kết luận điều tra đã lưu không xác lập một cuộc tấn công.",
            proposal: {
              id: "lab-icmp-ui",
              eligible: false,
              source_ip: null,
              expires: 0,
            },
          },
        ],
      },
    };
    await route.fulfill({ json: rendered });
  });
  await page.getByLabel("Hỏi trợ lý").fill("Các sự cố gần đây");
  await page.getByRole("button", { name: "Gửi", exact: true }).click();
  const log = page.getByRole("log");
  await expect(
    log.getByText(/10\.100\.27\.10.*172\.22\.50\.10/).first(),
  ).toBeVisible();
  await expect(log.getByText(/Wazuh 100101/).first()).toBeVisible();
  const fallback = log.getByRole("region", {
    name: "Stored analysis / Evidence-based summary",
  });
  await expect(fallback.getByText(/Không đề xuất chặn IP/)).toBeVisible();
  await expect(
    log.getByRole("heading", { name: "Nhận định AI", exact: true }),
  ).toHaveCount(0);
  await expect(log.getByText(/Kết luận đã lưu/).first()).toBeVisible();
  await expect(log.getByRole("button")).toHaveCount(0);
  await page.getByRole("link", { name: "Incident", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Hàng đợi incident", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "EN", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Incident queue", exact: true }),
  ).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  expect(
    await page.evaluate(() => localStorage.getItem("agentsoc.language")),
  ).toBe("en");
  await page.getByRole("button", { name: "Close assistant" }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "AI Assistant", exact: true }).click();
  const panel = page.getByRole("region", { name: "AI Assistant" });
  await expect(panel).toBeVisible();
  const bounds = await panel.boundingBox();
  expect(bounds!.width).toBeLessThanOrEqual(390);
  await expect(panel.getByRole("log").getByText(/Tìm thấy/)).toBeVisible();
});

test("Copilot restores the persisted thread after navigation and a new page", async ({
  page,
  context,
  browser,
}) => {
  await page.goto("/console");
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill("e2e-review-fixture-not-a-live-secret");
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await page.getByRole("button", { name: "AI Assistant", exact: true }).click();
  await page.getByRole("button", { name: "New Chat", exact: true }).click();
  const question = "Show recent incidents persistence fixture";
  await page.getByLabel("Ask the assistant").fill(question);
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page.getByRole("log").getByText(question)).toBeVisible();
  await page.getByRole("link", { name: "Alerts", exact: true }).click();
  await expect(page.getByRole("log").getByText(question)).toBeVisible();
  await page.getByRole("button", { name: "Close assistant" }).click();
  const reopened = await browser.newContext({
    storageState: await context.storageState(),
  });
  const resumed = await reopened.newPage();
  await resumed.goto("/console");
  await resumed
    .getByRole("button", { name: "AI Assistant", exact: true })
    .click();
  await expect(resumed.getByRole("log").getByText(question)).toBeVisible();
  await reopened.close();
});

test("a delayed reply stays in its original conversation", async ({ page }) => {
  await page.goto("/console");
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill("e2e-review-fixture-not-a-live-secret");
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await page.getByRole("button", { name: "AI Assistant", exact: true }).click();
  const picker = page.getByLabel("Conversation history");
  const creating = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/assistant/threads"),
  );
  await page.getByRole("button", { name: "New Chat", exact: true }).click();
  const original = (await (await creating).json()).id as string;
  await expect(picker).toHaveValue(original);
  const question = "Delayed persistence fixture";
  let release: () => void = () => {};
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/assistant/threads/*/messages", async (route) => {
    await blocked;
    await route.continue();
  });
  await page.getByLabel("Ask the assistant").fill(question);
  const sending = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      request.url().includes(original + "/messages"),
  );
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await sending;
  await page.getByRole("button", { name: "New Chat", exact: true }).click();
  await expect(picker).not.toHaveValue(original);
  const finished = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().includes(original + "/messages"),
  );
  release();
  expect((await finished).ok()).toBeTruthy();
  await expect(page.getByRole("log").getByText(question)).toHaveCount(0);
  await picker.selectOption(original);
  await expect(page.getByRole("log").getByText(question)).toBeVisible();
});
