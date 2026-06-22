"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { NodePicker } from "@/components/node-picker";
import { YamlDiff } from "@/components/yaml-diff";
import { api } from "@/lib/api";
import type { ExitNode, OutputProfile, UpstreamNode } from "@/lib/types";
import { Cloud, Eye, Loader2 } from "lucide-react";

type Form = {
  name: string;
  upstream_url: string;
  upstream_format: string;
  bridge_node_names: string[];
  exit_node_ids: string[];
  fetch_via_exit_node_id: string | null;
  custom_rules: string;
  enabled: boolean;
};

const empty: Form = {
  name: "",
  upstream_url: "",
  upstream_format: "auto",
  bridge_node_names: [],
  exit_node_ids: [],
  fetch_via_exit_node_id: null,
  custom_rules: "",
  enabled: true,
};

// 订阅格式下拉选项
const FORMAT_OPTIONS: { value: string; label: string }[] = [
  { value: "auto", label: "自动探测（默认）" },
  { value: "clash", label: "Clash / Mihomo YAML" },
  { value: "base64", label: "Base64 通用订阅" },
  { value: "uri", label: "裸节点 URI 列表" },
  { value: "sip008", label: "SIP008 JSON" },
];

export function ProfileEditor({
  open,
  onOpenChange,
  initial,
  exitNodes,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  initial: OutputProfile | null;
  exitNodes: ExitNode[];
  onSaved: () => void;
}) {
  const [form, setForm] = useState<Form>(empty);
  const [nodes, setNodes] = useState<UpstreamNode[]>([]);
  const [fetching, setFetching] = useState(false);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewText, setPreviewText] = useState("");
  const [previewUpstream, setPreviewUpstream] = useState("");
  const [previewing, setPreviewing] = useState(false);

  const reset = useCallback(() => {
    if (initial) {
      setForm({
        name: initial.name,
        upstream_url: initial.upstream_url,
        upstream_format: initial.upstream_format ?? "auto",
        bridge_node_names: initial.bridge_node_names,
        exit_node_ids: initial.exit_node_ids,
        fetch_via_exit_node_id: initial.fetch_via_exit_node_id ?? null,
        custom_rules: initial.custom_rules ?? "",
        enabled: initial.enabled,
      });
    } else {
      setForm(empty);
    }
    setNodes([]);
    setErr(null);
    setInfo(null);
    setDraftId(null);
  }, [initial]);

  useEffect(() => {
    if (open) reset();
  }, [open, reset]);

  // 打开时如果是编辑且有 last_upstream_yaml，自动拉一次节点列表
  useEffect(() => {
    if (!open || !initial) return;
    if (!initial.last_upstream_fetched_at) return;
    (async () => {
      try {
        const ns = await api.get<UpstreamNode[]>(
          `/api/profiles/${initial.id}/nodes`,
        );
        setNodes(ns);
      } catch {
        // 忽略，让用户手动拉取
      }
    })();
  }, [open, initial]);

  async function pullNodes() {
    setErr(null);
    setInfo(null);
    if (!initial) {
      // 新建：必须先保存一次才能拉(因为后端拉是按 profile id 走的)
      // 解决方式：先 POST 创建草稿(enabled=false)，再拉
      if (!form.name.trim() || !form.upstream_url.trim()) {
        setErr("先填好「名称」和「上游 URL」");
        return;
      }
      setFetching(true);
      try {
        const created = await api.post<OutputProfile>("/api/profiles", {
          name: form.name,
          upstream_url: form.upstream_url,
          upstream_format: form.upstream_format,
          bridge_node_names: [],
          exit_node_ids: form.exit_node_ids,
          fetch_via_exit_node_id: form.fetch_via_exit_node_id,
          custom_rules: form.custom_rules || null,
          enabled: false, // 草稿
        });
        await api.post(`/api/profiles/${created.id}/refresh-upstream`);
        const ns = await api.get<UpstreamNode[]>(
          `/api/profiles/${created.id}/nodes`,
        );
        setNodes(ns);
        setInfo(`已为新订阅创建草稿并拉到 ${ns.length} 个节点。保存后启用。`);
        setDraftId(created.id);
        onSaved(); // 让父组件 list 也刷新一下，看到草稿
      } catch (e: any) {
        setErr(e.message);
      } finally {
        setFetching(false);
      }
      return;
    }
    setFetching(true);
    try {
      await api.post(`/api/profiles/${initial.id}/refresh-upstream`);
      const ns = await api.get<UpstreamNode[]>(
        `/api/profiles/${initial.id}/nodes`,
      );
      setNodes(ns);
      setInfo(`已拉到 ${ns.length} 个节点。`);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setFetching(false);
    }
  }

  // 草稿 id：新建场景下点了"拉取节点"之后产生
  const [draftId, setDraftId] = useState<string | null>(null);
  const editingId = initial?.id ?? draftId;

  async function save() {
    setErr(null);
    if (!form.name.trim() || !form.upstream_url.trim()) {
      setErr("名称 / 上游 URL 必填");
      return;
    }
    if (form.exit_node_ids.length === 0) {
      setErr("至少选 1 个固定出口节点");
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name,
        upstream_url: form.upstream_url,
        upstream_format: form.upstream_format,
        bridge_node_names: form.bridge_node_names,
        exit_node_ids: form.exit_node_ids,
        fetch_via_exit_node_id: form.fetch_via_exit_node_id,
        custom_rules: form.custom_rules || null,
        enabled: form.enabled,
      };
      if (editingId) {
        await api.put(`/api/profiles/${editingId}`, payload);
      } else {
        await api.post("/api/profiles", payload);
      }
      onSaved();
      onOpenChange(false);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  async function preview() {
    if (!editingId) {
      setErr("请先「拉取节点」生成草稿，再预览");
      return;
    }
    if (form.bridge_node_names.length === 0) {
      setErr("先勾选至少一个跳板节点");
      return;
    }
    if (form.exit_node_ids.length === 0) {
      setErr("先选至少一个固定出口");
      return;
    }
    setPreviewing(true);
    try {
      // 预览前先保存当前编辑状态(确保 backend 用最新值生成)
      await api.put(`/api/profiles/${editingId}`, {
        name: form.name,
        upstream_url: form.upstream_url,
        upstream_format: form.upstream_format,
        bridge_node_names: form.bridge_node_names,
        exit_node_ids: form.exit_node_ids,
        fetch_via_exit_node_id: form.fetch_via_exit_node_id,
        custom_rules: form.custom_rules || null,
        enabled: form.enabled,
      });
      const token = localStorage.getItem("cb_token") || "";
      const headers = { Authorization: `Bearer ${token}` };
      const [newResp, upResp] = await Promise.all([
        fetch(`/api/profiles/${editingId}/preview`, { headers }),
        fetch(`/api/profiles/${editingId}/upstream`, { headers }),
      ]);
      const newText = await newResp.text();
      const upText = await upResp.text();
      if (!newResp.ok) throw new Error(newText);
      if (!upResp.ok) throw new Error(upText);
      setPreviewText(newText);
      setPreviewUpstream(upText);
      setPreviewOpen(true);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setPreviewing(false);
    }
  }

  function toggleExit(id: string) {
    const has = form.exit_node_ids.includes(id);
    setForm({
      ...form,
      exit_node_ids: has
        ? form.exit_node_ids.filter((x) => x !== id)
        : [...form.exit_node_ids, id],
    });
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange} size="fluid">
        <DialogHeader>
          <DialogTitle>{initial ? "编辑订阅配置" : "新建订阅配置"}</DialogTitle>
        </DialogHeader>
        <DialogContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>名称</Label>
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="HK 跳板"
              />
            </div>
            <div className="space-y-1">
              <Label>启用</Label>
              <label className="flex items-center gap-2 text-sm h-9">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) =>
                    setForm({ ...form, enabled: e.target.checked })
                  }
                />
                启用此配置（订阅地址可访问）
              </label>
            </div>
          </div>

          <div className="space-y-1">
            <Label>上游订阅 URL</Label>
            <div className="flex gap-2">
              <Input
                value={form.upstream_url}
                onChange={(e) =>
                  setForm({ ...form, upstream_url: e.target.value })
                }
                placeholder="https://your-provider.com/clash.yaml?token=xxx"
              />
              <Button
                type="button"
                variant="outline"
                onClick={pullNodes}
                disabled={fetching}
              >
                {fetching ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Cloud className="h-4 w-4" />
                )}
                拉取节点
              </Button>
            </div>
          </div>

          <div className="space-y-1">
            <Label>订阅格式</Label>
            <select
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              value={form.upstream_format}
              onChange={(e) =>
                setForm({ ...form, upstream_format: e.target.value })
              }
            >
              {FORMAT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
            <div className="text-xs text-muted-foreground">
              除 Clash/Mihomo YAML 外，还支持 Base64 通用订阅、裸节点 URI 列表（ss/vmess/vless/trojan/hysteria2）、SIP008。
              「自动探测」会按 clash → sip008 → base64 → uri 顺序识别；若机场格式固定，显式指定可更稳。
            </div>
          </div>

          <div className="space-y-1">
            <Label>拉取上游时使用的代理（绕过 IP 封禁）</Label>
            <select
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              value={form.fetch_via_exit_node_id ?? ""}
              onChange={(e) =>
                setForm({
                  ...form,
                  fetch_via_exit_node_id: e.target.value || null,
                })
              }
            >
              <option value="">直连（默认）</option>
              {exitNodes
                .map((n) => ({
                  ...n,
                  _type: (n.proxy_yaml.match(/^\s*type:\s*([a-z0-9]+)/im)?.[1] ?? "").toLowerCase(),
                }))
                .filter((n) => n._type === "socks5" || n._type === "http")
                .map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.name}（{n._type}）
                  </option>
                ))}
            </select>
            <div className="text-xs text-muted-foreground">
              某些机场对数据中心 IP 返回 403。指定一个 socks5/http 节点后，服务器拉上游订阅时会从该节点 IP 出去。
              其他类型节点（vmess/trojan 等）此处不可选。
            </div>
          </div>

          <div className="space-y-1">
            <Label>固定出口节点</Label>
            {exitNodes.length === 0 ? (
              <div className="text-xs text-muted-foreground p-2 border border-dashed border-border rounded-md">
                还没有固定出口节点。请先去「固定出口」页面添加。
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                {exitNodes.map((e) => {
                  const sel = form.exit_node_ids.includes(e.id);
                  return (
                    <button
                      key={e.id}
                      type="button"
                      onClick={() => toggleExit(e.id)}
                      className={`rounded-md border px-3 py-1.5 text-sm transition-colors ${
                        sel
                          ? "border-primary bg-primary text-primary-foreground"
                          : "border-border bg-background hover:bg-muted"
                      }`}
                    >
                      {e.name}
                      {!e.enabled && (
                        <span className="ml-1 text-xs opacity-70">(停用)</span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <Label>跳板节点（从上游勾选）</Label>
              {form.bridge_node_names.length > 0 && (
                <Badge variant="success">
                  已勾 {form.bridge_node_names.length} 个
                </Badge>
              )}
            </div>
            <NodePicker
              nodes={nodes}
              selected={form.bridge_node_names}
              onChange={(names) =>
                setForm({ ...form, bridge_node_names: names })
              }
            />
          </div>

          <div className="rounded-md border border-border bg-muted/40 p-3 text-xs text-muted-foreground space-y-1">
            <div className="font-medium text-foreground">注入策略</div>
            <div>• 完整保留上游订阅的 proxies / proxy-groups / rules，原机场分流规则不动。</div>
            <div>
              • proxies 末尾追加链路节点 <code>{`{exit}-via-{bridge}`}</code>（含 dialer-proxy）。
            </div>
            <div>
              • 末尾新增分组：每个出口一个 <code>{`{exit}-auto`}</code>（url-test，固定出口 IP，自动选最快跳板）；一个 <code>Bridge-Exit-auto</code>（url-test，跨出口跨跳板全自动选最快）；一个 <code>Bridge-Exit</code>（select，默认 Bridge-Exit-auto，可手动切到某个固定出口）。
            </div>
            <div>
              • 原 yaml 里每个 <code>type: select</code> 分组的下拉首项自动插入 <code>Bridge-Exit</code>，客户端打开就能切。
            </div>
          </div>

          {info && <div className="text-xs text-muted-foreground">{info}</div>}
          {err && <div className="text-sm text-destructive">{err}</div>}
        </DialogContent>
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={preview}
            disabled={previewing}
          >
            {previewing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Eye className="h-4 w-4" />
            )}
            预览 YAML
          </Button>
          <div className="flex-1" />
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={save} disabled={saving}>
            {saving ? "保存中..." : "保存"}
          </Button>
        </DialogFooter>
      </Dialog>

      <Dialog open={previewOpen} onOpenChange={setPreviewOpen} size="fluid">
        <DialogHeader>
          <DialogTitle>YAML 预览（左：上游原文 · 右：注入后产物）</DialogTitle>
        </DialogHeader>
        <DialogContent>
          <YamlDiff oldText={previewUpstream} newText={previewText} />
        </DialogContent>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => {
              navigator.clipboard.writeText(previewText);
            }}
          >
            复制注入后 YAML
          </Button>
          <Button variant="outline" onClick={() => setPreviewOpen(false)}>
            关闭
          </Button>
        </DialogFooter>
      </Dialog>
    </>
  );
}
