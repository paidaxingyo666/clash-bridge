"use client";

import { useEffect, useRef } from "react";

/// Cloudflare Turnstile widget. site_key 从 env (NEXT_PUBLIC_TURNSTILE_SITE_KEY) 取.
/// 没配 site_key 时不渲染 (本地开发场景), 父组件应根据 hasSiteKey() 决定是否要求 token.
const SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "";

export function hasTurnstileSiteKey(): boolean {
  return SITE_KEY.length > 0;
}

declare global {
  interface Window {
    turnstile?: {
      render: (
        el: HTMLElement | string,
        opts: {
          sitekey: string;
          callback?: (token: string) => void;
          "error-callback"?: () => void;
          "expired-callback"?: () => void;
          theme?: "light" | "dark" | "auto";
        },
      ) => string;
      reset: (widgetId?: string) => void;
      remove: (widgetId?: string) => void;
    };
  }
}

let scriptLoading: Promise<void> | null = null;
function loadScript(): Promise<void> {
  if (scriptLoading) return scriptLoading;
  if (typeof window !== "undefined" && window.turnstile)
    return Promise.resolve();
  scriptLoading = new Promise<void>((resolve, reject) => {
    const s = document.createElement("script");
    s.src =
      "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    s.async = true;
    s.defer = true;
    s.onload = () => resolve();
    s.onerror = () => {
      scriptLoading = null;
      reject(new Error("failed to load turnstile"));
    };
    document.head.appendChild(s);
  });
  return scriptLoading;
}

export function Turnstile({
  onToken,
}: {
  onToken: (token: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (!SITE_KEY) return;
    let cancelled = false;
    loadScript()
      .then(() => {
        if (cancelled || !ref.current || !window.turnstile) return;
        widgetIdRef.current = window.turnstile.render(ref.current, {
          sitekey: SITE_KEY,
          callback: onToken,
          "expired-callback": () => onToken(""),
          "error-callback": () => onToken(""),
          theme: "auto",
        });
      })
      .catch(() => {
        // 加载失败时静默 — 后端会因为没拿到 token 直接报错, 用户能看到
      });
    return () => {
      cancelled = true;
      if (widgetIdRef.current && window.turnstile) {
        try {
          window.turnstile.remove(widgetIdRef.current);
        } catch {}
      }
    };
    // 故意只在挂载时跑一次, onToken 变化不重渲
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!SITE_KEY) return null;
  return <div ref={ref} className="my-2" />;
}
