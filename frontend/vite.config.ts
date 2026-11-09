import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { compile } from "@tailwindcss/node";
import { dirname } from "node:path";

// The console uses custom CSS and an explicit list of Tailwind utilities.
// Compile that list with Tailwind's JS compiler; no native filesystem scanner.
function consoleCss(): Plugin {
  return {
    name: "agentsoc-console-css",
    enforce: "pre",
    async transform(source, id) {
      const file = id.split("?", 1)[0];
      if (!file.replaceAll("\\", "/").endsWith("/src/style.css")) return;
      const compiler = await compile(source, {
        base: dirname(file),
        onDependency: (dependency) => this.addWatchFile(dependency),
      });
      if (compiler.root !== "none" || compiler.sources.length) {
        throw new Error(
          "Console CSS requires source(none) and @source inline(...) for Tailwind utilities.",
        );
      }
      return { code: compiler.build([]), map: null };
    },
  };
}

export default defineConfig({
  plugins: [react(), consoleCss()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/health": "http://127.0.0.1:8000",
      "/ready": "http://127.0.0.1:8000",
    },
  },
});
