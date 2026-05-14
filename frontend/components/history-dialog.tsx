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
import { Badge } from "@/components/ui/badge";
import { YamlDiff } from "@/components/yaml-diff";
import { api, API_BASE } from "@/lib/api";
import type { HistoryItem } from "@/lib/types";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";

async function fetchText(path: string): Promise<string> {
  const token = localStorage.getItem("cb_token") || "";
  const r = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const text = await r.text();
  if (!r.ok) throw new Error(text || `HTTP ${r.status}`);
  return text;
}

export function HistoryDialog({
  profileId,
  profileName,
  open,
  onOpenChange,
}: {
  profileId: string | null;
  profileName: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const [selected, setSelected] = useState<HistoryItem | null>(null);
  const [curYaml, setCurYaml] = useState("");
  const [prevYaml, setPrevYaml] = useState("");
  const [diffLoading, setDiffLoading] = useState(false);

  const load = useCallback(async () => {
    if (!profileId) return;
    setLoading(true);
    setErr(null);
    try {
      const rows = await api.get<HistoryItem[]>(
        `/api/profiles/${profileId}/history`,
      );
      setItems(rows);
      // 默认选中最新一条
      if (rows.length > 0) setSelected(rows[0]);
      else setSelected(null);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  }, [profileId]);

  useEffect(() => {
    if (open && profileId) load();
    if (!open) {
      setItems([]);
      setSelected(null);
      setCurYaml("");
      setPrevYaml("");
    }
  }, [open, profileId, load]);

  // 选中变化 -> 拉这条 yaml + 上一条 yaml
  useEffect(() => {
    if (!selected || !profileId) {
      setCurYaml("");
      setPrevYaml("");
      return;
    }
    setDiffLoading(true);
    (async () => {
      try {
        const cur = await fetchText(
          `/api/profiles/${profileId}/history/${selected.id}`,
        );
        let prev = "";
        if (selected.has_previous) {
          prev = await fetchText(
            `/api/profiles/${profileId}/history/${selected.id}/previous`,
          );
        }
        setCurYaml(cur);
        setPrevYaml(prev);
      } catch (e: any) {
        setErr(e.message);
      } finally {
        setDiffLoading(false);
      }
    })();
  }, [selected, profileId]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange} size="fluid">
      <DialogHeader>
        <DialogTitle>上游订阅历史 — {profileName}</DialogTitle>
      </DialogHeader>
      <DialogContent>
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> 加载中
          </div>
        ) : err ? (
          <div className="text-sm text-destructive">{err}</div>
        ) : items.length === 0 ? (
          <div className="text-sm text-muted-foreground text-center py-6">
            还没有快照。手动刷新上游后这里会出现第一条记录；
            <br />
            或者等后台自动刷新（默认 60 分钟一次，可在 .env 调）。
          </div>
        ) : (
          <div className="grid grid-cols-12 gap-3 min-h-[60vh]">
            {/* 左：历史列表 */}
            <div className="col-span-4 border border-border rounded-md overflow-auto max-h-[70vh]">
              <ul>
                {items.map((h, idx) => {
                  const active = selected?.id === h.id;
                  return (
                    <li
                      key={h.id}
                      onClick={() => setSelected(h)}
                      className={cn(
                        "px-3 py-2 border-b border-border cursor-pointer hover:bg-muted/50 text-sm",
                        active && "bg-muted",
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium">
                          {new Date(h.fetched_at).toLocaleString()}
                        </span>
                        <Badge
                          variant={h.trigger_kind === "manual" ? "default" : "muted"}
                          className="text-[10px]"
                        >
                          {h.trigger_kind}
                        </Badge>
                      </div>
                      <div className="text-xs text-muted-foreground mt-1 flex items-center gap-2">
                        <span>{h.proxy_count} 节点</span>
                        <span className="font-mono">
                          {h.content_hash.slice(0, 8)}
                        </span>
                        {idx === 0 && (
                          <span className="text-green-700">最新</span>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>

            {/* 右：diff */}
            <div className="col-span-8">
              {!selected ? (
                <div className="text-sm text-muted-foreground">
                  选一条历史看它和上一版的差异
                </div>
              ) : diffLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" /> 加载 diff
                </div>
              ) : !selected.has_previous ? (
                <div className="text-sm text-muted-foreground space-y-2">
                  <p>这是最早的一条快照，没有上一版可对比。</p>
                  <pre className="font-mono text-[12px] leading-[1.4] whitespace-pre-wrap border border-border rounded-md p-3 max-h-[60vh] overflow-auto">
                    {curYaml}
                  </pre>
                </div>
              ) : (
                <YamlDiff
                  oldText={prevYaml}
                  newText={curYaml}
                  leftLabel="上一版"
                  rightLabel="该版"
                />
              )}
            </div>
          </div>
        )}
      </DialogContent>
      <DialogFooter>
        <Button variant="outline" onClick={() => onOpenChange(false)}>
          关闭
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
