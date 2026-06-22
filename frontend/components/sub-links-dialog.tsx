"use client";

import { useEffect, useState } from "react";
import QRCode from "qrcode";
import {
  Dialog,
  DialogHeader,
  DialogTitle,
  DialogContent,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Copy, Check, Download, QrCode } from "lucide-react";
import type { OutputProfile } from "@/lib/types";

/// 各输出格式 → /sub/:token/:format 的后缀 + 是否支持固定出口链路(relay)。
/// base64/Surge/QX 无法表达 dialer-proxy 链路, 含链路的 profile 后端会 415, 这里直接禁用。
const FORMATS: { id: string; label: string; hint: string; relay: boolean }[] = [
  { id: "clash.yaml", label: "Clash", hint: "Clash / Mihomo / Clash Verge", relay: true },
  { id: "singbox.json", label: "sing-box", hint: "sing-box 1.9+", relay: true },
  { id: "sub.txt", label: "base64", hint: "V2rayN / Shadowrocket 等通用订阅", relay: false },
  { id: "surge.conf", label: "Surge", hint: "Surge", relay: false },
  { id: "quanx.conf", label: "Quantumult X", hint: "Quantumult X", relay: false },
];

/// 订阅链接弹窗: 一个 profile 的多格式订阅 URL, 每个可复制 / 扫码 / 打开。
/// 含固定出口链路时, 不支持 relay 的格式(base64/Surge/QX)灰显禁用并提示。
export function SubLinksDialog({
  open,
  onOpenChange,
  profile,
  base,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  profile: OutputProfile | null;
  base: string;
}) {
  const [copied, setCopied] = useState<string | null>(null);
  const [qrFmt, setQrFmt] = useState<string | null>(null);
  const [qrSvg, setQrSvg] = useState<string>("");

  // 是否含固定出口链路: 已生成的看 chain_count; 未生成的按"选了出口+跳板"推断。
  const hasRelay =
    !!profile &&
    (profile.cached_chain_count > 0 ||
      (profile.exit_node_ids.length > 0 && profile.bridge_node_names.length > 0));

  const urlFor = (fmt: string) =>
    profile ? `${base.replace(/\/$/, "")}/sub/${profile.sub_token}/${fmt}` : "";

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(null), 1500);
    return () => clearTimeout(t);
  }, [copied]);

  // 二维码在前端本地生成 (URL 含 token, 不外发)。
  useEffect(() => {
    if (!qrFmt || !profile) {
      setQrSvg("");
      return;
    }
    let cancelled = false;
    QRCode.toString(urlFor(qrFmt), {
      type: "svg",
      margin: 1,
      width: 220,
      errorCorrectionLevel: "M",
      color: { dark: "#000000", light: "#ffffff" },
    })
      .then((s: string) => {
        if (!cancelled) setQrSvg(s);
      })
      .catch(() => {
        if (!cancelled) setQrSvg("");
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qrFmt, profile?.sub_token, base]);

  // 关闭时复位
  useEffect(() => {
    if (!open) {
      setQrFmt(null);
      setCopied(null);
    }
  }, [open]);

  if (!profile) return null;

  async function copy(fmt: string) {
    try {
      await navigator.clipboard.writeText(urlFor(fmt));
      setCopied(fmt);
    } catch {
      // 非安全上下文 (http) 没有 clipboard API; 静默降级, 用户可手动选中
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange} size="md">
      <DialogHeader>
        <DialogTitle>订阅链接 — {profile.name}</DialogTitle>
      </DialogHeader>
      <DialogContent>
        {hasRelay && (
          <p className="text-xs text-muted-foreground">
            此订阅含<strong>固定出口链路</strong>，仅 Clash / sing-box 能完整表达；
            base64 / Surge / Quantumult X 已禁用（这些格式无法表达链式出口）。
          </p>
        )}
        <div className="space-y-2">
          {FORMATS.map((f) => {
            const disabled = hasRelay && !f.relay;
            const url = urlFor(f.id);
            return (
              <div
                key={f.id}
                className={`rounded-lg border p-3 ${disabled ? "opacity-50" : ""}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-medium">{f.label}</div>
                    <div className="text-xs text-muted-foreground">
                      {disabled ? "含固定出口链路，此格式不可用" : f.hint}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <Button
                      size="icon"
                      variant="ghost"
                      title="复制链接"
                      disabled={disabled}
                      onClick={() => copy(f.id)}
                    >
                      {copied === f.id ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      title="二维码"
                      disabled={disabled}
                      onClick={() => setQrFmt(qrFmt === f.id ? null : f.id)}
                    >
                      <QrCode className="h-4 w-4" />
                    </Button>
                    {disabled ? (
                      <span className="inline-flex h-9 w-9 items-center justify-center text-muted-foreground">
                        <Download className="h-4 w-4" />
                      </span>
                    ) : (
                      <a
                        href={url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex h-9 w-9 items-center justify-center rounded-md hover:bg-muted"
                        title="打开 / 下载"
                      >
                        <Download className="h-4 w-4" />
                      </a>
                    )}
                  </div>
                </div>
                {!disabled && (
                  <div className="mt-1 font-mono text-[11px] break-all text-muted-foreground">
                    {url}
                  </div>
                )}
                {qrFmt === f.id && !disabled && (
                  <div
                    className="mt-3 mx-auto w-fit rounded-lg bg-white p-3"
                    role="img"
                    aria-label={`${f.label} 订阅二维码`}
                    /* svg 由 qrcode 库本地生成, 内容可控、无外部脚本 */
                    dangerouslySetInnerHTML={{ __html: qrSvg }}
                  />
                )}
              </div>
            );
          })}
        </div>
      </DialogContent>
    </Dialog>
  );
}
