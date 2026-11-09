import { test, expect } from "@playwright/test";
import fs from "node:fs";

test("empty state, Wazuh pipeline, ledger, analyst note and dry-run review", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/console");
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill("e2e-review-fixture-not-a-live-secret");
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  await expect(page.getByText("No records to display")).toBeVisible();
  const fixture = fs
    .readFileSync("../datasets/demo.jsonl", "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  for (const alert of fixture) {
    const response = await page.request.post("/ingest", {
      headers: { Authorization: "Bearer e2e-ingest-fixture-not-a-live-secret" },
      data: alert,
    });
    expect(response.status()).toBe(202);
  }
  await expect
    .poll(async () => {
      const r = await page.request.get("/api/v1/incidents");
      return (await r.json()).items[0]?.workflow_status;
    })
    .toBe("review");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("link", { name: /INC-/ }).first()).toBeVisible();
  await page.screenshot({ path: "test-results/overview.png", fullPage: true });
  await page.getByRole("link", { name: "Alerts", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: /Received alerts/ }),
  ).toBeVisible();
  await page.getByRole("link", { name: "demo-host-1", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Original JSON" }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Incidents", exact: true }).click();
  await page.getByRole("link", { name: /INC-/ }).first().click();
  await expect(
    page.getByRole("heading", { name: "Decision summary" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Case integrations", exact: true }),
  ).toBeVisible();
  await page
    .getByLabel("Add operational context")
    .fill("Browser smoke verified the cited evidence.");
  await page.getByRole("button", { name: "Add note", exact: true }).click();
  await expect(
    page.getByText("Browser smoke verified the cited evidence."),
  ).toBeVisible();
  await page
    .getByRole("button", { name: /^[a-f0-9]{12}$/ })
    .first()
    .click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("dialog").getByText("NET", { exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Guarded input" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Close detail" }).click();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Approve response" }).click();
  await expect(
    page.getByText("dry_run", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Approve response" }),
  ).toHaveCount(0);
  for (const [link, heading] of [
    ["Investigation ledger", "Investigation ledger"],
    ["Response review", "Response review"],
    ["System health", "System health"],
    ["Audit log", "Audit log"],
  ]) {
    await page.getByRole("link", { name: link, exact: true }).click();
    await expect(
      page.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
  }
  await expect(
    page.getByText("response.approve", { exact: true }).first(),
  ).toBeVisible();
  await expect(page.getByText("response.approve", { exact: true })).toHaveCount(
    2,
  );
  expect(errors).toEqual([]);
});

test("mobile navigation, keyboard focus and session cookie isolation", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/console");
  await page.getByLabel("Username", { exact: true }).focus();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Password", { exact: true })).toBeFocused();
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page
    .getByLabel("Password", { exact: true })
    .fill("e2e-review-fixture-not-a-live-secret");
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  expect(await page.evaluate(() => document.cookie)).not.toContain(
    "agentsoc_session",
  );
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  await page
    .getByRole("navigation", { name: "Primary navigation" })
    .getByRole("link", { name: "System health", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "System health", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "External integrations", exact: true }),
  ).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    )
    .toBe(true);
  await page.screenshot({
    path: "test-results/system-mobile.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Sign in to workspace" }),
  ).toBeVisible();
});
