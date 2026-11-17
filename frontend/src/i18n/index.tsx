import { useSyncExternalStore } from "react";
import en from "./en.json";
import vi from "./vi.json";

export type Language = "en" | "vi";
function saved(): Language {
  try {
    return localStorage.getItem("agentsoc.language") === "vi" ? "vi" : "en";
  } catch {
    return "en";
  }
}
let language: Language = saved();
document.documentElement.lang = language;
const listeners = new Set<() => void>();
export function setLanguage(value: Language) {
  language = value;
  document.documentElement.lang = value;
  try {
    localStorage.setItem("agentsoc.language", value);
  } catch {
    /* Storage can be unavailable. */
  }
  listeners.forEach((notify) => notify());
}
export function useLanguage() {
  const current = useSyncExternalStore(
    (notify) => {
      listeners.add(notify);
      return () => {
        listeners.delete(notify);
      };
    },
    () => language,
  );
  return [current, setLanguage] as const;
}
export function t(key: string): string {
  const dictionary: Record<string, string> = language === "vi" ? vi : en;
  return dictionary[key] ?? key;
}
export function LanguageSwitcher() {
  const [current, change] = useLanguage();
  return (
    <div className="language-switch" aria-label={t("Language")}>
      {(["en", "vi"] as const).map((value, index) => (
        <span key={value}>
          {index > 0 && " | "}
          <button
            type="button"
            aria-pressed={current === value}
            onClick={() => change(value)}
          >
            {value.toUpperCase()}
          </button>
        </span>
      ))}
    </div>
  );
}
