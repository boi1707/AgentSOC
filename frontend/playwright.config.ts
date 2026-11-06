import { defineConfig } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const python = path.join(
  root,
  ".venv",
  process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
);
const chrome = "C:/Program Files/Google/Chrome/Application/chrome.exe";
export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  retries: 0,
  use: {
    baseURL: "http://127.0.0.1:8765",
    viewport: { width: 1440, height: 1000 },
    launchOptions:
      process.platform === "win32" && fs.existsSync(chrome)
        ? { executablePath: chrome }
        : {},
    trace: "retain-on-failure",
  },
  webServer: {
    command: `"${python}" -m scripts.e2e_server`,
    cwd: root,
    url: "http://127.0.0.1:8765/live",
    reuseExistingServer: false,
    timeout: 30000,
  },
  reporter: "list",
});
