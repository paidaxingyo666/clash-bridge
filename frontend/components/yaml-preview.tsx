"use client";

export function YamlPreview({ text }: { text: string }) {
  return (
    <pre className="max-h-[70vh] overflow-auto rounded-md border border-border bg-muted/40 p-3 text-xs leading-5 font-mono whitespace-pre">
      {text}
    </pre>
  );
}
