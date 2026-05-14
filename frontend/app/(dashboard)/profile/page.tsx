"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { api } from "@/lib/api";
import { saveAuth, getUser } from "@/lib/auth";
import type { UserView } from "@/lib/types";

export default function ProfilePage() {
  const [user, setUser] = useState<UserView | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setUser(getUser<UserView>());
    api
      .get<UserView>("/api/me")
      .then((u) => {
        setUser(u);
        const token = localStorage.getItem("cb_token") || "";
        saveAuth(token, u);
      })
      .catch((e: any) => setErr(e.message));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">账号</h1>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>账户信息</CardTitle>
          <CardDescription>
            订阅 token 在每条「订阅配置」上独立管理，可以在订阅配置页面重置
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div>
            <div className="text-muted-foreground text-xs">用户名</div>
            <div className="font-medium">{user?.username ?? "—"}</div>
          </div>
          <div>
            <div className="text-muted-foreground text-xs">创建时间</div>
            <div>{user?.created_at ? new Date(user.created_at).toLocaleString() : "—"}</div>
          </div>
          {err && <div className="text-destructive">{err}</div>}
        </CardContent>
      </Card>
    </div>
  );
}
