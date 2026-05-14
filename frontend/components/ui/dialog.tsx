"use client";

import * as React from "react";
import { cn } from "@/lib/cn";

type DialogSize = "md" | "lg" | "xl" | "2xl" | "fluid";

const sizeClass: Record<DialogSize, string> = {
  md: "max-w-lg",
  lg: "max-w-2xl",
  xl: "max-w-4xl",
  "2xl": "max-w-6xl",
  // fluid: 视口越大越宽, 但不超过 80rem (1280px)
  fluid: "max-w-[min(96vw,80rem)]",
};

export function Dialog({
  open,
  onOpenChange,
  size = "md",
  children,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  size?: DialogSize;
  children: React.ReactNode;
}) {
  React.useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onOpenChange(false);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onOpenChange]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-black/40"
        onClick={() => onOpenChange(false)}
      />
      <div
        className={cn(
          "relative z-10 w-full max-h-[90vh] flex flex-col overflow-hidden rounded-lg border border-border bg-background shadow-lg",
          sizeClass[size],
        )}
      >
        {children}
      </div>
    </div>
  );
}

export function DialogHeader({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("p-5 border-b border-border shrink-0", className)}
      {...props}
    />
  );
}

export function DialogTitle({
  className,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn("text-lg font-semibold", className)} {...props} />;
}

export function DialogContent({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "p-5 space-y-4 overflow-y-auto overflow-x-hidden flex-1 min-w-0",
        className,
      )}
      {...props}
    />
  );
}

export function DialogFooter({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "p-5 border-t border-border flex flex-wrap justify-end items-center gap-2 shrink-0",
        className,
      )}
      {...props}
    />
  );
}
