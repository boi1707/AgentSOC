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

test("unsent drafts survive refresh and older pages stay loaded", async ({
  page,
}) => {
  await page.goto("/console");
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill("e2e-review-fixture-not-a-live-secret");
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await page.route(
    /\/api\/v1\/assistant\/threads\/[a-f0-9]{32}(\?|$)/,
    async (route) => {
      const url = new URL(route.request().url());
      url.searchParams.set("limit", "2");
      await route.continue({ url: url.toString() });
    },
  );
  await page.getByRole("button", { name: "AI Assistant", exact: true }).click();
  const picker = page.getByLabel("Conversation history");
  const created = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/assistant/threads"),
  );
  await page.getByRole("button", { name: "New Chat", exact: true }).click();
  const original = (await (await created).json()).id as string;
  await expect(picker).toHaveValue(original);
  const composer = page.getByLabel("Ask the assistant");
  for (let i = 1; i <= 4; i++) {
    const text = "History pagination fixture " + i;
    await composer.fill(text);
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByRole("log").getByText(text)).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Send", exact: true }),
    ).toBeDisabled();
  }
  const unsent = "Unsent private draft";
  await composer.fill(unsent);
  await expect(page.getByText("Draft saved", { exact: true })).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "AI Assistant", exact: true }).click();
  await expect(composer).toHaveValue(unsent);
  const log = page.getByRole("log");
  await expect(log.getByText("History pagination fixture 1")).toHaveCount(0);
  const refreshed = page.waitForResponse(
    (response) =>
      response.request().method() === "GET" &&
      response.url().includes(original + "?limit="),
  );
  await log
    .getByRole("button", { name: "Older messages", exact: true })
    .click();
  await expect(log.getByText("History pagination fixture 1")).toBeVisible();
  await expect(
    log.getByRole("button", { name: "Older messages", exact: true }),
  ).toHaveCount(0);
  await refreshed;
  await expect(log.getByText("History pagination fixture 1")).toHaveCount(1);
  await expect(log.getByText("History pagination fixture 4")).toHaveCount(1);
  await expect(log.getByText(unsent)).toHaveCount(0);
});

test("chat approval requests a confirmation only for the selected intent", async ({
  page,
}) => {
  await page.goto("/console");
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill("e2e-review-fixture-not-a-live-secret");
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await page.getByRole("button", { name: "AI Assistant", exact: true }).click();
  const creating = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/assistant/threads"),
  );
  await page.getByRole("button", { name: "New Chat", exact: true }).click();
  const tid = (await (await creating).json()).id as string;
  const selected = "a".repeat(32);
  const other = "b".repeat(32);
  let confirmed: string | undefined;
  const messages: object[] = [];
  await page.route("**/assistant/threads/" + tid, async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    const actions = [selected, other].map((id) => ({
      id,
      case_id: "case-" + id[0],
      run_id: "current-run",
      target: "10.100.27.10",
      approval_policy: "manual_analyst",
      status: confirmed === id ? "dry_run" : "prepared",
      mode: "dry-run",
      expires: Date.now() / 1000 + 300,
      ttl: 3600,
      justification: "Fixture",
      evidence_ids: ["fixture-evidence"],
      evidence_gaps: [],
      original_judge_verdict: "review",
    }));
    await route.fulfill({ response, json: { ...body, messages, actions } });
  });
  await page.route(
    "**/assistant/threads/" + tid + "/messages",
    async (route) => {
      const payload = route.request().postDataJSON();
      const entry = {
        id: payload.request_key,
        question: payload.message,
        status: "completed",
        answer: {
          summary: "Fixture confirmation",
          notice: "",
          facts: [],
          citations: [],
          analysis: [],
          confirmation: payload.selected_intent_id
            ? { intent_id: payload.selected_intent_id, decision: "approve" }
            : undefined,
        },
      };
      messages.push(entry);
      await route.fulfill({ json: entry });
    },
  );
  await page.route(
    "**/assistant/threads/" + tid + "/actions/*",
    async (route) => {
      confirmed = new URL(route.request().url()).pathname.split("/").at(-1);
      expect(route.request().postDataJSON()).toEqual({ decision: "approve" });
      await route.fulfill({ json: { status: "dry_run" } });
    },
  );
  const sendApprove = async () => {
    await page.getByLabel("Ask the assistant").fill("Approve");
    await page.getByRole("button", { name: "Send", exact: true }).click();
  };
  await sendApprove();
  await expect(page.getByText("Fixture confirmation")).toHaveCount(1);
  const control = page.getByRole("button", {
    name: "Confirm approval",
    exact: true,
  });
  await expect(control).toHaveCount(0);
  expect(confirmed).toBeUndefined();
  const targetCard = page
    .locator("article.assistant-action")
    .filter({ hasText: "case-a" });
  await targetCard
    .getByRole("button", { name: "Select for chat", exact: true })
    .click();
  await sendApprove();
  await expect(control).toHaveCount(1);
  expect(confirmed).toBeUndefined();
  await control.click();
  await expect(control).toHaveCount(0);
  expect(confirmed).toBe(selected);
});
