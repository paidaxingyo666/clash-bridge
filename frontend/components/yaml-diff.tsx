"use client";

import { diffLines } from "diff";
import { useMemo } from "react";
import { cn } from "@/lib/cn";

type Row = {
  /** common = 左右一样;  remove = 只在左;  add = 只在右;  modify = 左右都有且都标 */
  kind: "common" | "add" | "remove" | "modify";
  left: string;
  right: string;
  leftLn: number | null;
  rightLn: number | null;
};

function computeRows(oldText: string, newText: string): Row[] {
  const chunks = diffLines(oldText, newText);
  const rows: Row[] = [];
  let leftLn = 1;
  let rightLn = 1;

  const splitLines = (s: string): string[] => {
    const a = s.split("\n");
    // 因为 chunk.value 以 \n 结尾会多出一个空串
    if (a.length > 0 && a[a.length - 1] === "") a.pop();
    return a;
  };

  for (let i = 0; i < chunks.length; i++) {
    const c = chunks[i];
    const lines = splitLines(c.value);
    if (lines.length === 0) continue;

    if (c.removed && i + 1 < chunks.length && chunks[i + 1].added) {
      const next = chunks[i + 1];
      const rLines = splitLines(next.value);
      const max = Math.max(lines.length, rLines.length);
      for (let j = 0; j < max; j++) {
        const hasL = j < lines.length;
        const hasR = j < rLines.length;
        rows.push({
          kind: hasL && hasR ? "modify" : hasL ? "remove" : "add",
          left: hasL ? lines[j] : "",
          right: hasR ? rLines[j] : "",
          leftLn: hasL ? leftLn + j : null,
          rightLn: hasR ? rightLn + j : null,
        });
      }
      leftLn += lines.length;
      rightLn += rLines.length;
      i++; // 已处理掉下一个 chunk
    } else if (c.removed) {
      for (let j = 0; j < lines.length; j++) {
        rows.push({
          kind: "remove",
          left: lines[j],
          right: "",
          leftLn: leftLn + j,
          rightLn: null,
        });
      }
      leftLn += lines.length;
    } else if (c.added) {
      for (let j = 0; j < lines.length; j++) {
        rows.push({
          kind: "add",
          left: "",
          right: lines[j],
          leftLn: null,
          rightLn: rightLn + j,
        });
      }
      rightLn += lines.length;
    } else {
      for (let j = 0; j < lines.length; j++) {
        rows.push({
          kind: "common",
          left: lines[j],
          right: lines[j],
          leftLn: leftLn + j,
          rightLn: rightLn + j,
        });
      }
      leftLn += lines.length;
      rightLn += lines.length;
    }
  }
  return rows;
}

/** 简单 YAML 高亮：key、注释、字符串、数字、布尔 */
function highlightYamlLine(line: string): React.ReactNode[] {
  if (line.trim().startsWith("#")) {
    return [
      <span key={0} className="text-zinc-400 italic">
        {line}
      </span>,
    ];
  }
  // 匹配开头缩进/横线，然后 key 和 value
  const m = line.match(/^(\s*-?\s*)([A-Za-z_][\w-]*)(:)(.*)?$/);
  if (m) {
    return [
      <span key="i">{m[1]}</span>,
      <span key="k" className="text-sky-700 dark:text-sky-300">
        {m[2]}
      </span>,
      <span key="c" className="text-zinc-500">
        {m[3]}
      </span>,
      m[4] ? (
        <span key="v">{highlightValue(m[4])}</span>
      ) : null,
    ];
  }
  // dash-only line eg "- foo"
  const m2 = line.match(/^(\s*-\s*)(.*)$/);
  if (m2) {
    return [<span key="i">{m2[1]}</span>, <span key="v">{highlightValue(m2[2])}</span>];
  }
  return [<span key="0">{line}</span>];
}

function highlightValue(v: string): React.ReactNode {
  const t = v.trim();
  if (t === "") return v;
  // 数字
  if (/^-?\d+(\.\d+)?$/.test(t)) {
    return <span className="text-amber-700 dark:text-amber-300">{v}</span>;
  }
  // bool / null
  if (/^(true|false|null|~)$/i.test(t)) {
    return <span className="text-purple-700 dark:text-purple-300">{v}</span>;
  }
  // 引号字符串
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return <span className="text-emerald-700 dark:text-emerald-300">{v}</span>;
  }
  return <span>{v}</span>;
}

const bgLeft = {
  common: "",
  remove: "bg-red-50",
  add: "bg-zinc-50/40 text-zinc-400",
  modify: "bg-red-50",
} as const;

const bgRight = {
  common: "",
  add: "bg-green-50",
  remove: "bg-zinc-50/40 text-zinc-400",
  modify: "bg-green-50",
} as const;

const gutterStyle = {
  common: "text-zinc-400",
  add: "text-green-700 bg-green-100",
  remove: "text-red-700 bg-red-100",
  modify: "text-amber-700 bg-amber-100",
} as const;

export function YamlDiff({
  oldText,
  newText,
  leftLabel = "上游原文",
  rightLabel = "注入后",
}: {
  oldText: string;
  newText: string;
  leftLabel?: string;
  rightLabel?: string;
}) {
  const rows = useMemo(() => computeRows(oldText, newText), [oldText, newText]);

  const stats = useMemo(() => {
    let add = 0,
      rem = 0,
      mod = 0;
    for (const r of rows) {
      if (r.kind === "add") add++;
      else if (r.kind === "remove") rem++;
      else if (r.kind === "modify") mod++;
    }
    return { add, rem, mod };
  }, [rows]);

  return (
    <div className="border border-border rounded-md overflow-hidden">
      <div className="grid grid-cols-2 bg-muted/60 text-xs font-medium px-3 py-1.5 border-b border-border">
        <div className="flex items-center gap-2">
          <span>{leftLabel}</span>
          <span className="text-muted-foreground">
            {stats.rem + stats.mod} 行被替换
          </span>
        </div>
        <div className="flex items-center gap-2 border-l border-border pl-3">
          <span>{rightLabel}</span>
          <span className="text-green-700">+{stats.add + stats.mod}</span>
          <span className="text-red-700">-{stats.rem + stats.mod}</span>
        </div>
      </div>
      <div className="overflow-auto max-h-[70vh] font-mono text-[12px] leading-[1.4]">
        {rows.map((r, i) => (
          <div key={i} className="flex w-full">
            {/* left line no */}
            <div
              className={cn(
                "shrink-0 w-10 text-right px-1 select-none border-r border-border",
                gutterStyle[r.kind],
              )}
            >
              {r.leftLn ?? ""}
            </div>
            {/* left content */}
            <div
              className={cn(
                "flex-1 px-2 whitespace-pre-wrap break-all border-r border-border",
                bgLeft[r.kind],
              )}
            >
              {r.left === "" ? " " : highlightYamlLine(r.left)}
            </div>
            {/* right line no */}
            <div
              className={cn(
                "shrink-0 w-10 text-right px-1 select-none border-r border-border",
                gutterStyle[r.kind],
              )}
            >
              {r.rightLn ?? ""}
            </div>
            {/* right content */}
            <div
              className={cn(
                "flex-1 px-2 whitespace-pre-wrap break-all",
                bgRight[r.kind],
              )}
            >
              {r.right === "" ? " " : highlightYamlLine(r.right)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
