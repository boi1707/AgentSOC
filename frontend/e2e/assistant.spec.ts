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
});
