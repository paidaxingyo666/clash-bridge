"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { api } from "@/lib/api";
import { saveAuth } from "@/lib/auth";
import type { AuthOutput } from "@/lib/types";

const USERNAME_RE = /^[A-Za-z0-9_.-]+$/;

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function validate(): string | null {
    const u = username.trim();
    if (mode === "register") {
      if (u.length < 3 || u.length > 32) return "用户名长度需 3-32 位";
      if (!USERNAME_RE.test(u))
        return "用户名只能含字母、数字、下划线、点和短横线";
      if (password.length < 6) return "密码至少 6 位";
      if (password.length > 128) return "密码不能超过 128 字节";
      if (password !== confirm) return "两次密码不一致";
    } else {
      if (!u) return "请输入用户名";
      if (!password) return "请输入密码";
    }
    return null;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    const v = validate();
    if (v) {
      setErr(v);
      return;
    }
    setLoading(true);
    try {
      const path = mode === "login" ? "/api/auth/login" : "/api/auth/register";
      const out = await api.post<AuthOutput>(
        path,
        { username: username.trim(), password },
        false,
      );
      saveAuth(out.token, out.user);
      router.push("/profiles");
    } catch (e: any) {
      setErr(e.message || "请求失败");
    } finally {
      setLoading(false);
    }
  }

  function switchMode() {
    setMode(mode === "login" ? "register" : "login");
    setErr(null);
    setConfirm("");
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/40 p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Clash Bridge</CardTitle>
          <CardDescription>
            {mode === "login" ? "登录账号" : "注册新账号"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-3">
            <div className="space-y-1">
              <Label>用户名</Label>
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoComplete="username"
                minLength={mode === "register" ? 3 : 1}
                maxLength={32}
                pattern={mode === "register" ? "[A-Za-z0-9_.\\-]{3,32}" : undefined}
                placeholder={
                  mode === "register" ? "3-32 位字母/数字/_.-" : ""
                }
              />
            </div>
            <div className="space-y-1">
              <Label>密码</Label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete={
                  mode === "register" ? "new-password" : "current-password"
                }
                minLength={6}
                maxLength={128}
                placeholder={mode === "register" ? "6-128 位" : ""}
              />
            </div>
            {mode === "register" && (
              <div className="space-y-1">
                <Label>确认密码</Label>
                <Input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                  autoComplete="new-password"
                  minLength={6}
                  maxLength={128}
                  placeholder="再次输入密码"
                />
              </div>
            )}
            {err && <div className="text-sm text-destructive">{err}</div>}
            <Button type="submit" disabled={loading} className="w-full">
              {loading ? "处理中..." : mode === "login" ? "登录" : "注册"}
            </Button>
            <button
              type="button"
              className="w-full text-xs text-muted-foreground hover:underline"
              onClick={switchMode}
            >
              {mode === "login" ? "没有账号? 注册一个" : "已有账号? 去登录"}
            </button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
