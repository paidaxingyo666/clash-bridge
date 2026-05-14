"use client";

import { useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { UpstreamNode } from "@/lib/types";

export function NodePicker({
  nodes,
  selected,
  onChange,
  emptyHint,
}: {
  nodes: UpstreamNode[];
  selected: string[];
  onChange: (names: string[]) => void;
  emptyHint?: string;
}) {
  const [q, setQ] = useState("");
  const filtered = useMemo(() => {
    const lq = q.trim().toLowerCase();
    if (!lq) return nodes;
    return nodes.filter(
      (n) =>
        n.name.toLowerCase().includes(lq) ||
        (n.server ?? "").toLowerCase().includes(lq) ||
        (n.type ?? "").toLowerCase().includes(lq),
    );
  }, [nodes, q]);
  const sel = useMemo(() => new Set(selected), [selected]);
  const filteredSelectedCount = filtered.filter((n) => sel.has(n.name)).length;
  const allFilteredSelected =
    filtered.length > 0 && filteredSelectedCount === filtered.length;

  function toggle(name: string) {
    const next = new Set(sel);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    onChange([...next]);
  }

  function toggleAllFiltered() {
    if (allFilteredSelected) {
      const remaining = selected.filter(
        (n) => !filtered.some((f) => f.name === n),
      );
      onChange(remaining);
    } else {
      const next = new Set(sel);
      for (const f of filtered) next.add(f.name);
      onChange([...next]);
    }
  }

  function clearAll() {
    onChange([]);
  }

  if (!nodes.length) {
    return (
      <div className="text-sm text-muted-foreground p-3 border border-dashed border-border rounded-md text-center">
        {emptyHint ?? "尚未拉取上游节点。先填好上游 URL 再点「拉取节点」。"}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="搜索节点 name / server / type"
          className="flex-1 min-w-[200px]"
        />
        <Button type="button" variant="outline" size="sm" onClick={toggleAllFiltered}>
          {allFilteredSelected ? "取消勾选(当前筛选)" : "全选(当前筛选)"}
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={clearAll}>
          清空
        </Button>
        <Badge variant="muted">
          已选 {selected.length} / 共 {nodes.length}
        </Badge>
      </div>

      <div className="max-h-[56vh] overflow-auto border border-border rounded-md">
        <table className="w-full text-sm table-fixed">
          <thead className="bg-muted/50 sticky top-0">
            <tr className="text-left text-xs text-muted-foreground">
              <th className="px-2 py-1 w-10"></th>
              <th className="px-2 py-1 w-2/5">name</th>
              <th className="px-2 py-1 w-24">type</th>
              <th className="px-2 py-1">server:port</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((n) => {
              const checked = sel.has(n.name);
              return (
                <tr
                  key={n.name}
                  className="border-t border-border hover:bg-muted/30 cursor-pointer"
                  onClick={() => toggle(n.name)}
                >
                  <td className="px-2 py-1">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggle(n.name)}
                      onClick={(e) => e.stopPropagation()}
                    />
                  </td>
                  <td className="px-2 py-1 font-medium truncate">{n.name}</td>
                  <td className="px-2 py-1 text-xs text-muted-foreground truncate">
                    {n.type ?? "—"}
                  </td>
                  <td className="px-2 py-1 text-xs text-muted-foreground truncate">
                    {n.server ?? "—"}
                    {n.port ? `:${n.port}` : ""}
                  </td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={4} className="text-center text-xs text-muted-foreground py-4">
                  没有匹配的节点
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
