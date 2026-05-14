"use client";

import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Table, THead, TBody, TR, TH, TD } from "@/components/ui/table";
import { ProxyEditor } from "@/components/proxy-editor";
import { api } from "@/lib/api";
import type { ExitNode } from "@/lib/types";
import { Plus, Pencil, Trash2, RefreshCw } from "lucide-react";
import {
  emptyForm,
  formToYaml,
  yamlToForm,
  validateForm,
} from "@/lib/proxy-schema";

const INITIAL_YAML = formToYaml(emptyForm("trojan"));

export default function ExitNodesPage() {
  const [items, setItems] = useState<ExitNode[]>([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<ExitNode | null>(null);
  const [form, setForm] = useState({
    name: "",
    proxy_yaml: INITIAL_YAML,
    enabled: true,
  });
  const [yamlValid, setYamlValid] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const rows = await api.get<ExitNode[]>("/api/exit-nodes");
      setItems(rows);
    } catch (e: any) {
      setErr(e.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function startCreate() {
    setEditing(null);
    setForm({ name: "", proxy_yaml: INITIAL_YAML, enabled: true });
    setYamlValid(true);
    setErr(null);
    setOpen(true);
  }

  function startEdit(row: ExitNode) {
    setEditing(row);
    setForm({
      name: row.name,
      proxy_yaml: row.proxy_yaml,
      enabled: row.enabled,
    });
    // 先假设有效, 编辑器挂载后会通过 onValidityChange 调正
    setYamlValid(true);
    setErr(null);
    setOpen(true);
  }

  async function submit() {
    setErr(null);
    // 最后一次校验 (YAML 模式下用户可能直接粘了一份, 没经过表单)
    try {
      const f = yamlToForm(form.proxy_yaml);
      const errs = validateForm(f);
      const keys = Object.keys(errs);
      if (keys.length > 0) {
        setErr(
          "配置不完整: " + keys.map((k) => `${k} ${errs[k]}`).join("; "),
        );
        return;
      }
    } catch (e: any) {
      setErr(e?.message ?? "YAML 不合法");
      return;
    }
    if (!form.name.trim()) {
      setErr("请填写后台标识名");
      return;
    }
    try {
      if (editing) {
        await api.put(`/api/exit-nodes/${editing.id}`, form);
      } else {
        await api.post("/api/exit-nodes", form);
      }
      setOpen(false);
      await load();
    } catch (e: any) {
      setErr(e.message);
    }
  }

  async function remove(row: ExitNode) {
    if (!confirm(`确认删除 "${row.name}"?`)) return;
    await api.delete(`/api/exit-nodes/${row.id}`);
    await load();
  }

  function nodeTypeFromYaml(yaml: string): string {
    try {
      const f = yamlToForm(yaml);
      return f.type;
    } catch {
      const m = yaml.match(/^type:\s*([\w-]+)/m);
      return m?.[1] ?? "—";
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">固定出口节点</h1>
          <p className="text-sm text-muted-foreground mt-1">
            表单填字段或直接粘 YAML，5 种主流协议有协议级校验
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={load}>
            <RefreshCw className="h-4 w-4" /> 刷新
          </Button>
          <Button onClick={startCreate}>
            <Plus className="h-4 w-4" /> 新增
          </Button>
        </div>
      </div>

      {err && !open && <div className="text-sm text-destructive">{err}</div>}

      <Card>
        <CardContent className="p-0">
          <Table>
            <THead>
              <TR>
                <TH>名称</TH>
                <TH>协议</TH>
                <TH>启用</TH>
                <TH>YAML 摘要</TH>
                <TH className="text-right">操作</TH>
              </TR>
            </THead>
            <TBody>
              {items.map((row) => (
                <TR key={row.id}>
                  <TD className="font-medium">{row.name}</TD>
                  <TD className="text-xs">
                    <Badge variant="muted">{nodeTypeFromYaml(row.proxy_yaml)}</Badge>
                  </TD>
                  <TD>
                    {row.enabled ? (
                      <Badge variant="success">启用</Badge>
                    ) : (
                      <Badge variant="muted">停用</Badge>
                    )}
                  </TD>
                  <TD className="text-xs font-mono max-w-md truncate">
                    {row.proxy_yaml.split("\n").slice(0, 2).join(" | ")}
                  </TD>
                  <TD className="text-right">
                    <Button size="sm" variant="ghost" onClick={() => startEdit(row)}>
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => remove(row)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TD>
                </TR>
              ))}
              {items.length === 0 && (
                <TR>
                  <TD colSpan={5} className="text-center text-muted-foreground py-8">
                    暂无数据
                  </TD>
                </TR>
              )}
            </TBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen} size="xl">
        <DialogHeader>
          <DialogTitle>{editing ? "编辑出口节点" : "新增出口节点"}</DialogTitle>
        </DialogHeader>
        <DialogContent>
          <div className="space-y-1">
            <Label>后台标识名 (用于这个管理页面区分多条配置)</Label>
            <Input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="例如: 香港-trojan、新加坡-vmess"
            />
          </div>

          <ProxyEditor
            yaml={form.proxy_yaml}
            onYamlChange={(y) =>
              setForm((p) => (p.proxy_yaml === y ? p : { ...p, proxy_yaml: y }))
            }
            onValidityChange={setYamlValid}
          />

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            />
            启用
          </label>

          {err && <div className="text-sm text-destructive">{err}</div>}
        </DialogContent>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            取消
          </Button>
          <Button onClick={submit} disabled={!yamlValid}>
            保存
          </Button>
        </DialogFooter>
      </Dialog>
    </div>
  );
}
