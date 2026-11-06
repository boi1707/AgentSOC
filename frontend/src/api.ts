import { useEffect, useState } from "react";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
let csrf = "";
export function setCsrf(value: string) {
  csrf = value;
}
export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch("/api/v1" + path, {
    ...options,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      ...options.headers,
    },
  });
  const body = await response
    .json()
    .catch(() => ({ detail: "Server returned an unreadable response" }));
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/auth/"))
      window.dispatchEvent(new Event("agentsoc:unauthorized"));
    throw new ApiError(
      response.status,
      body.error?.message ?? body.detail ?? "Request failed",
    );
  }
  return body as T;
}
export function useData<T>(path: string) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [updated, setUpdated] = useState<number>();
  const [version, setVersion] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    api<T>(path, { signal: controller.signal })
      .then((value) => {
        setData(value);
        setError(undefined);
        setUpdated(Date.now());
      })
      .catch((e: unknown) => {
        if (e instanceof Error && e.name !== "AbortError") setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [path, version]);
  useEffect(() => {
    const timer = setInterval(() => setVersion((v) => v + 1), 15000);
    return () => clearInterval(timer);
  }, []);
  return {
    data,
    error,
    loading,
    updated,
    refresh: () => setVersion((v) => v + 1),
  };
}
