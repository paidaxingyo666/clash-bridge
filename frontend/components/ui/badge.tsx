import * as React from "react";
import { cn } from "@/lib/cn";

export function Badge({
  className,
  variant = "default",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & {
  variant?: "default" | "success" | "danger" | "muted";
}) {
  const styles = {
    default: "bg-primary text-primary-foreground",
    success: "bg-green-600 text-white",
    danger: "bg-destructive text-destructive-foreground",
    muted: "bg-muted text-foreground",
  }[variant];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-xs font-medium",
        styles,
        className,
      )}
      {...props}
    />
  );
}
