import { getToken } from "./auth";

/// 前端对外可见的 URL (用于展示给用户复制的订阅地址).
/// 留空时会走当前页面域名 — 比如部署在 https://example.com 上, 订阅地址就是
/// https://example.com/sub/.../clash.yaml. 本地开发可以填 http://127.0.0.1:8080.
export const PUBLIC_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "";

export type ApiError = { error: string };

async function request<T>(
  path: string,
  init: RequestInit & { auth?: boolean } = {},
): Promise<T> {
  const { auth = true, headers, ...rest } = init;
  const h: Record<string, string> = {
    "Content-Type": "application/json",
    ...(headers as Record<string, string> | undefined),
  };
  if (auth) {
    const t = getToken();
    if (t) h["Authorization"] = `Bearer ${t}`;
  }
  // 一律走相对路径; Next.js rewrite 会反代到 backend (见 next.config.mjs).
  const resp = await fetch(path, { ...rest, headers: h });
  const text = await resp.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!resp.ok) {
    const msg =
      (data && typeof data === "object" && "error" in (data as any) && (data as any).error) ||
      `HTTP ${resp.status}`;
    throw new Error(String(msg));
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown, auth = true) =>
    request<T>(path, {
      method: "POST",
      body: body !== undefined ? JSON.stringify(body) : undefined,
      auth,
    }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "PUT",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};
