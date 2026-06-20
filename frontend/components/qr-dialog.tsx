"use client";

import { useEffect, useState } from "react";
import QRCode from "qrcode";
import {
  Dialog,
  DialogHeader,
  DialogTitle,
  DialogContent,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";

/// 订阅二维码弹窗: 把订阅 URL 在浏览器本地编码成二维码 (SVG), 供客户端扫码导入.
/// 二维码完全在前端生成, URL (含 token) 不会发给任何第三方服务.
export function QrDialog({
  open,
  onOpenChange,
  url,
  name,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  url: string;
  name?: string;
}) {
  const [svg, setSvg] = useState<string>("");
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open || !url) {
      setSvg("");
      return;
    }
    let cancelled = false;
    setErr(null);
    QRCode.toString(url, {
      type: "svg",
      margin: 1,
      width: 256,
      errorCorrectionLevel: "M",
      // 显式指定黑白, 不依赖 currentColor — 保证暗色模式下浅色模块也是不透明白
      color: { dark: "#000000", light: "#ffffff" },
    })
      .then((s) => {
        if (!cancelled) setSvg(s);
      })
      .catch((e) => {
        if (!cancelled) setErr(String(e?.message ?? e));
      });
    return () => {
      cancelled = true;
    };
  }, [open, url]);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
    } catch {
      // 非安全上下文 (http) 或老浏览器没有 clipboard API; 静默降级, 不抛未捕获 rejection
      setErr("当前环境不支持自动复制, 请手动选中下方地址复制");
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange} size="md">
      <DialogHeader>
        <DialogTitle>订阅二维码{name ? ` — ${name}` : ""}</DialogTitle>
      </DialogHeader>
      <DialogContent>
        <p className="text-sm text-muted-foreground text-center">
          用 Clash / 代理客户端的「扫码导入」扫描下方二维码即可添加订阅
        </p>
        {err ? (
          <div className="text-sm text-destructive text-center">
            二维码生成失败: {err}
          </div>
        ) : (
          <div
            className="mx-auto w-fit rounded-lg bg-white p-4"
            role="img"
            aria-label={`订阅二维码${name ? ` ${name}` : ""}`}
            /* svg 由 qrcode 库在本地生成, 内容可控、无外部脚本 */
            dangerouslySetInnerHTML={{ __html: svg }}
          />
        )}
        <div className="mx-auto max-w-full break-all text-center font-mono text-xs text-muted-foreground">
          {url}
        </div>
      </DialogContent>
      <DialogFooter>
        <Button variant="outline" onClick={copy}>
          {copied ? (
            <Check className="h-4 w-4" />
          ) : (
            <Copy className="h-4 w-4" />
          )}
          {copied ? "已复制" : "复制链接"}
        </Button>
        <Button onClick={() => onOpenChange(false)}>关闭</Button>
      </DialogFooter>
    </Dialog>
  );
}
