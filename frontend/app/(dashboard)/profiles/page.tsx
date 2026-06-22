"use client";

import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, THead, TBody, TR, TH, TD } from "@/components/ui/table";
import { ProfileEditor } from "@/components/profile-editor";
import { HistoryDialog } from "@/components/history-dialog";
import { QrDialog } from "@/components/qr-dialog";
import { SubLinksDialog } from "@/components/sub-links-dialog";
import { api, PUBLIC_URL } from "@/lib/api";
import type {
  ExitNode,
  GenerateResult,
  OutputProfile,
} from "@/lib/types";
import {
  Plus,
  RefreshCw,
  Pencil,
  Trash2,
  Copy,
  QrCode,
  Download,
  Sparkles,
  KeyRound,
  Cloud,
  History,
  Link2,
} from "lucide-react";

export default function ProfilesPage() {
  const [items, setItems] = useState<OutputProfile[]>([]);
  const [exits, setExits] = useState<ExitNode[]>([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<OutputProfile | null>(null);
  const [historyFor, setHistoryFor] = useState<OutputProfile | null>(null);
  const [qrFor, setQrFor] = useState<OutputProfile | null>(null);
  const [linksFor, setLinksFor] = useState<OutputProfile | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [profs, ens] = await Promise.all([
        api.get<OutputProfile[]>("/api/profiles"),
        api.get<ExitNode[]>("/api/exit-nodes"),
      ]);
      setItems(profs);
      setExits(ens);
    } catch (e: any) {
      setErr(e.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function startCreate() {
    setEditing(null);
    setOpen(true);
  }
  function startEdit(p: OutputProfile) {
    setEditing(p);
    setOpen(true);
  }

  async function remove(p: OutputProfile) {
    if (!confirm(`确认删除「${p.name}」?`)) return;
    await api.delete(`/api/profiles/${p.id}`);
    await load();
  }

  async function refresh(p: OutputProfile) {
    setBusyId(p.id);
    setErr(null);
    try {
      await api.post(`/api/profiles/${p.id}/refresh-upstream`);
      await load();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusyId(null);
    }
  }

  async function generate(p: OutputProfile) {
    setBusyId(p.id);
    setErr(null);
    try {
      const r = await api.post<GenerateResult>(`/api/profiles/${p.id}/generate`);
      if (r.missing_bridges.length > 0) {
        alert(
          `生成成功。注意：${r.missing_bridges.length} 个已勾选的跳板节点在最新上游里找不到：\n` +
            r.missing_bridges.join("\n"),
        );
      }
      await load();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusyId(null);
    }
  }

  async function resetToken(p: OutputProfile) {
    if (!confirm(`重置后旧订阅地址立即失效，确认?`)) return;
    setBusyId(p.id);
    try {
      await api.post(`/api/profiles/${p.id}/reset-token`);
      await load();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusyId(null);
    }
  }

  function subUrl(p: OutputProfile) {
    // 优先用 build-time 注入的 PUBLIC_URL; 没设就用浏览器当前 origin
    const base =
      PUBLIC_URL ||
      (typeof window !== "undefined" ? window.location.origin : "");
    return `${base.replace(/\/$/, "")}/sub/${p.sub_token}/clash.yaml`;
  }

  async function copyUrl(p: OutputProfile) {
    await navigator.clipboard.writeText(subUrl(p));
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">订阅配置</h1>
          <p className="text-sm text-muted-foreground mt-1">
            每条配置 = 一个独立的输出订阅 URL
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={load}>
            <RefreshCw className="h-4 w-4" /> 刷新列表
          </Button>
          <Button onClick={startCreate}>
            <Plus className="h-4 w-4" /> 新建订阅配置
          </Button>
        </div>
      </div>

      {err && <div className="text-sm text-destructive">{err}</div>}

      <Card>
        <CardContent className="p-0">
          <Table>
            <THead>
              <TR>
                <TH>名称</TH>
                <TH>订阅地址</TH>
                <TH>跳板/出口</TH>
                <TH>缓存统计</TH>
                <TH>最近上游</TH>
                <TH>状态</TH>
                <TH className="text-right">操作</TH>
              </TR>
            </THead>
            <TBody>
              {items.map((p) => {
                const url = subUrl(p);
                const busy = busyId === p.id;
                return (
                  <TR key={p.id}>
                    <TD className="font-medium">{p.name}</TD>
                    <TD>
                      <div className="font-mono text-xs break-all max-w-[260px]">
                        {url}
                      </div>
                    </TD>
                    <TD className="text-xs">
                      <div>跳板: {p.bridge_node_names.length}</div>
                      <div>出口: {p.exit_node_ids.length}</div>
                    </TD>
                    <TD className="text-xs">
                      {p.cached_at ? (
                        <>
                          <div>
                            上游 {p.cached_upstream_count} / 跳板{" "}
                            {p.cached_bridge_count} / 链路 {p.cached_chain_count}
                          </div>
                          <div className="text-muted-foreground">
                            {new Date(p.cached_at).toLocaleString()}
                          </div>
                          {p.cached_missing_bridges.length > 0 && (
                            <div className="text-destructive">
                              {p.cached_missing_bridges.length} 个跳板失效
                            </div>
                          )}
                        </>
                      ) : (
                        <span className="text-muted-foreground">未生成</span>
                      )}
                    </TD>
                    <TD className="text-xs">
                      {p.last_upstream_fetched_at ? (
                        <>
                          <div>
                            {new Date(
                              p.last_upstream_fetched_at,
                            ).toLocaleString()}
                          </div>
                          <div
                            className={
                              p.last_upstream_fetch_status === "success"
                                ? "text-green-600"
                                : "text-destructive"
                            }
                          >
                            {p.last_upstream_fetch_status === "success"
                              ? "成功"
                              : "失败"}
                          </div>
                          {p.last_upstream_fetch_error && (
                            <div
                              className="text-destructive truncate max-w-[180px] cursor-help"
                              title={p.last_upstream_fetch_error}
                            >
                              {p.last_upstream_fetch_error}
                            </div>
                          )}
                          {p.last_upstream_fetch_status === "error" &&
                            p.cached_at && (
                              <Badge variant="warning" className="mt-1">
                                使用缓存中
                              </Badge>
                            )}
                        </>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TD>
                    <TD>
                      {p.enabled ? (
                        <Badge variant="success">启用</Badge>
                      ) : (
                        <Badge variant="muted">停用</Badge>
                      )}
                    </TD>
                    <TD className="text-right">
                      <div className="inline-flex gap-0.5">
                        <Button
                          size="icon"
                          variant="ghost"
                          title="刷新上游"
                          onClick={() => refresh(p)}
                          disabled={busy}
                        >
                          <Cloud
                            className={
                              busy ? "h-4 w-4 animate-spin" : "h-4 w-4"
                            }
                          />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="重新生成 YAML"
                          onClick={() => generate(p)}
                          disabled={busy}
                        >
                          <Sparkles className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="上游历史"
                          onClick={() => setHistoryFor(p)}
                        >
                          <History className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="复制订阅地址 (Clash)"
                          onClick={() => copyUrl(p)}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="全部格式订阅链接"
                          onClick={() => setLinksFor(p)}
                        >
                          <Link2 className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="订阅二维码"
                          onClick={() => setQrFor(p)}
                        >
                          <QrCode className="h-4 w-4" />
                        </Button>
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex h-9 w-9 items-center justify-center rounded-md hover:bg-muted"
                          title="下载 YAML"
                        >
                          <Download className="h-4 w-4" />
                        </a>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="重置 token"
                          onClick={() => resetToken(p)}
                          disabled={busy}
                        >
                          <KeyRound className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="编辑"
                          onClick={() => startEdit(p)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="删除"
                          onClick={() => remove(p)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TD>
                  </TR>
                );
              })}
              {items.length === 0 && (
                <TR>
                  <TD colSpan={7} className="text-center text-muted-foreground py-12">
                    暂无订阅配置。点右上「新建订阅配置」开始。
                  </TD>
                </TR>
              )}
            </TBody>
          </Table>
        </CardContent>
      </Card>

      <ProfileEditor
        open={open}
        onOpenChange={setOpen}
        initial={editing}
        exitNodes={exits}
        onSaved={load}
      />

      <HistoryDialog
        open={historyFor !== null}
        onOpenChange={(v) => !v && setHistoryFor(null)}
        profileId={historyFor?.id ?? null}
        profileName={historyFor?.name ?? ""}
      />

      <QrDialog
        open={qrFor !== null}
        onOpenChange={(v) => !v && setQrFor(null)}
        url={qrFor ? subUrl(qrFor) : ""}
        name={qrFor?.name}
      />

      <SubLinksDialog
        open={linksFor !== null}
        onOpenChange={(v) => !v && setLinksFor(null)}
        profile={linksFor}
        base={
          PUBLIC_URL ||
          (typeof window !== "undefined" ? window.location.origin : "")
        }
      />
    </div>
  );
}
