"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  ListChecks,
  ServerCog,
  UserCog,
  LogOut,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/button";
import { clearAuth } from "@/lib/auth";

const items = [
  { href: "/profiles", label: "订阅配置", icon: ListChecks },
  { href: "/exit-nodes", label: "固定出口", icon: ServerCog },
  { href: "/profile", label: "账号", icon: UserCog },
];

export function AppSidebar() {
  const pathname = usePathname();
  const router = useRouter();
  return (
    <aside className="h-screen w-60 shrink-0 border-r border-border bg-background flex flex-col">
      <div className="p-5">
        <div className="text-lg font-semibold">Clash Bridge</div>
        <div className="text-xs text-muted-foreground mt-1">
          跳板订阅生成器
        </div>
      </div>
      <nav className="flex-1 px-2 space-y-0.5">
        {items.map((it) => {
          const active = pathname?.startsWith(it.href);
          const Icon = it.icon;
          return (
            <Link
              key={it.href}
              href={it.href}
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-muted",
                active && "bg-muted font-medium",
              )}
            >
              <Icon className="h-4 w-4" />
              {it.label}
            </Link>
          );
        })}
      </nav>
      <div className="p-3 border-t border-border">
        <Button
          variant="ghost"
          className="w-full justify-start"
          onClick={() => {
            clearAuth();
            router.push("/login");
          }}
        >
          <LogOut className="h-4 w-4" />
          退出登录
        </Button>
      </div>
    </aside>
  );
}
