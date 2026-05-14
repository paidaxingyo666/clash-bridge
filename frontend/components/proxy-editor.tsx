"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/cn";
import {
  PROXY_TYPES,
  SS_CIPHERS,
  SSR_CIPHERS,
  SSR_OBFS,
  SSR_PROTOCOLS,
  VMESS_CIPHERS,
  NETWORK_TYPES,
  TUIC_CC,
  TUIC_UDP_MODES,
  HYSTERIA_PROTOCOLS,
  emptyForm,
  formToYaml,
  yamlToForm,
  validateForm,
  type FieldErrors,
  type ProxyForm,
  type ProxyType,
} from "@/lib/proxy-schema";

type Mode = "form" | "yaml";

export function ProxyEditor({
  yaml,
  onYamlChange,
  onValidityChange,
}: {
  yaml: string;
  onYamlChange: (yaml: string) => void;
  onValidityChange?: (valid: boolean) => void;
}) {
  const [mode, setMode] = useState<Mode>("form");
  const [form, setForm] = useState<ProxyForm>(() => {
    try {
      return yamlToForm(yaml);
    } catch {
      return emptyForm("trojan");
    }
  });
  const [yamlErr, setYamlErr] = useState<string | null>(null);

  const fieldErrors: FieldErrors = useMemo(() => validateForm(form), [form]);
  const errorCount = Object.keys(fieldErrors).length;

  const onYamlChangeRef = useRef(onYamlChange);
  const onValidityChangeRef = useRef(onValidityChange);
  useEffect(() => {
    onYamlChangeRef.current = onYamlChange;
    onValidityChangeRef.current = onValidityChange;
  });

  const lastEmittedRef = useRef<string | null>(null);

  useEffect(() => {
    if (mode !== "form") return;
    const y = formToYaml(form);
    if (lastEmittedRef.current === y) return;
    lastEmittedRef.current = y;
    onYamlChangeRef.current(y);
    onValidityChangeRef.current?.(errorCount === 0);
  }, [form, mode, errorCount]);

  function switchMode(next: Mode) {
    if (next === mode) return;
    if (next === "form") {
      try {
        const f = yamlToForm(yaml);
        setForm(f);
        setYamlErr(null);
      } catch (e: any) {
        setYamlErr(e?.message ?? "YAML 不合法");
      }
    }
    setMode(next);
  }

  function patch<K extends keyof ProxyForm>(k: K, v: ProxyForm[K]) {
    setForm((prev) => ({ ...prev, [k]: v }));
  }

  function changeType(t: ProxyType) {
    setForm((prev) => {
      const next = emptyForm(t);
      next.name = prev.name;
      next.server = prev.server;
      next.port = prev.port;
      return next;
    });
  }

  return (
    <Tabs value={mode} onValueChange={(v) => switchMode(v as Mode)}>
      <TabsList>
        <TabsTrigger value="form">表单</TabsTrigger>
        <TabsTrigger value="yaml">YAML</TabsTrigger>
      </TabsList>

      <TabsContent value="form">
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="协议" error={fieldErrors.type}>
              <select
                className="flex h-9 w-full rounded-md border border-border bg-background px-3 text-sm"
                value={form.type}
                onChange={(e) => changeType(e.target.value as ProxyType)}
              >
                {PROXY_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="name (节点名)" error={fieldErrors.name}>
              <TInput
                value={form.name}
                onChange={(v) => patch("name", v)}
                placeholder="fixed-exit-sg"
                invalid={!!fieldErrors.name}
              />
            </Field>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="server" error={fieldErrors.server}>
              <TInput
                value={form.server}
                onChange={(v) => patch("server", v)}
                placeholder="exit.example.com"
                invalid={!!fieldErrors.server}
              />
            </Field>
            <Field label="port" error={fieldErrors.port}>
              <Input
                type="number"
                min={1}
                max={65535}
                value={form.port === "" ? "" : form.port}
                onChange={(e) => {
                  const v = e.target.value;
                  patch("port", v === "" ? "" : Number(v));
                }}
                className={fieldErrors.port ? "border-destructive" : ""}
              />
            </Field>
          </div>

          {form.type === "trojan" && (
            <TrojanFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "ss" && (
            <SsFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "ssr" && (
            <SsrFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "vmess" && (
            <VmessFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "vless" && (
            <VlessFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "hysteria2" && (
            <Hysteria2Fields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "hysteria" && (
            <HysteriaFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "tuic" && (
            <TuicFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "snell" && (
            <SnellFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "wireguard" && (
            <WireguardFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {form.type === "anytls" && (
            <AnyTlsFields form={form} patch={patch} errs={fieldErrors} />
          )}
          {(form.type === "socks5" || form.type === "http") && (
            <UserPassTlsFields form={form} patch={patch} errs={fieldErrors} />
          )}

          {form.type !== "http" && (
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={!!form.udp}
                onChange={(e) => patch("udp", e.target.checked)}
              />
              udp (允许 UDP)
            </label>
          )}

          {errorCount > 0 && (
            <p className="text-xs text-destructive">
              共 {errorCount} 处需修正，错误已在对应字段下方提示
            </p>
          )}
        </div>
      </TabsContent>

      <TabsContent value="yaml">
        <div className="space-y-2">
          <Textarea
            rows={14}
            value={yaml}
            onChange={(e) => {
              onYamlChange(e.target.value);
              setYamlErr(null);
              try {
                const f = yamlToForm(e.target.value);
                const errs = validateForm(f);
                onValidityChange?.(Object.keys(errs).length === 0);
              } catch {
                onValidityChange?.(false);
              }
            }}
            placeholder={`name: fixed-exit\ntype: trojan\nserver: example.com\nport: 443\npassword: ...`}
          />
          {yamlErr && <div className="text-sm text-destructive">{yamlErr}</div>}
          <p className="text-xs text-muted-foreground">
            切到「表单」时会尝试解析当前 YAML。表单不支持的高级字段(ws-opts/grpc-opts/reality 等)可在 YAML 模式自由编辑。
          </p>
        </div>
      </TabsContent>
    </Tabs>
  );
}

// ---- 通用 helpers ----

function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <Label>{label}</Label>
      {children}
      {hint && !error && (
        <p className="text-xs text-muted-foreground">{hint}</p>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}

function TInput({
  value,
  onChange,
  placeholder,
  invalid,
  type = "text",
}: {
  value: string | number | undefined;
  onChange: (v: string) => void;
  placeholder?: string;
  invalid?: boolean;
  type?: string;
}) {
  return (
    <Input
      type={type}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={cn(invalid && "border-destructive")}
    />
  );
}

function TSelect({
  value,
  onChange,
  options,
  invalid,
}: {
  value: string | undefined;
  onChange: (v: string) => void;
  options: readonly string[];
  invalid?: boolean;
}) {
  return (
    <select
      className={cn(
        "flex h-9 w-full rounded-md border border-border bg-background px-3 text-sm",
        invalid && "border-destructive",
      )}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value)}
    >
      {options.map((c) => (
        <option key={c} value={c}>
          {c}
        </option>
      ))}
    </select>
  );
}

type Patch = <K extends keyof ProxyForm>(k: K, v: ProxyForm[K]) => void;

interface FieldProps {
  form: ProxyForm;
  patch: Patch;
  errs: FieldErrors;
}

// ---- 协议子表单 ----

function TrojanFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <Field label="password" error={errs.password}>
        <TInput
          value={form.password}
          onChange={(v) => patch("password", v)}
          invalid={!!errs.password}
        />
      </Field>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="sni (可选)" hint="同 server 或证书 CN" error={errs.sni}>
          <TInput value={form.sni} onChange={(v) => patch("sni", v)} />
        </Field>
        <CheckboxField
          label="skip-cert-verify (跳过证书校验)"
          checked={!!form["skip-cert-verify"]}
          onChange={(v) => patch("skip-cert-verify", v)}
        />
      </div>
    </div>
  );
}

function SsFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3 grid grid-cols-1 md:grid-cols-2 gap-3">
      <Field label="cipher" error={errs.cipher}>
        <TSelect
          value={form.cipher}
          onChange={(v) => patch("cipher", v)}
          options={SS_CIPHERS}
          invalid={!!errs.cipher}
        />
      </Field>
      <Field label="password" error={errs.password}>
        <TInput
          value={form.password}
          onChange={(v) => patch("password", v)}
          invalid={!!errs.password}
        />
      </Field>
    </div>
  );
}

function SsrFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="cipher" error={errs.cipher}>
          <TSelect
            value={form.cipher}
            onChange={(v) => patch("cipher", v)}
            options={SSR_CIPHERS}
            invalid={!!errs.cipher}
          />
        </Field>
        <Field label="password" error={errs.password}>
          <TInput
            value={form.password}
            onChange={(v) => patch("password", v)}
            invalid={!!errs.password}
          />
        </Field>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="obfs" error={errs.obfs}>
          <TSelect
            value={form.obfs}
            onChange={(v) => patch("obfs", v)}
            options={SSR_OBFS}
            invalid={!!errs.obfs}
          />
        </Field>
        <Field label="protocol" error={errs.protocol}>
          <TSelect
            value={form.protocol}
            onChange={(v) => patch("protocol", v)}
            options={SSR_PROTOCOLS}
            invalid={!!errs.protocol}
          />
        </Field>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="obfs-param (可选)">
          <TInput
            value={form["obfs-param"]}
            onChange={(v) => patch("obfs-param", v)}
          />
        </Field>
        <Field label="protocol-param (可选)">
          <TInput
            value={form["protocol-param"]}
            onChange={(v) => patch("protocol-param", v)}
          />
        </Field>
      </div>
    </div>
  );
}

function VmessFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <Field label="uuid" error={errs.uuid}>
        <TInput
          value={form.uuid}
          onChange={(v) => patch("uuid", v)}
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          invalid={!!errs.uuid}
        />
      </Field>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Field label="alterId">
          <Input
            type="number"
            min={0}
            value={form.alterId === "" ? "" : (form.alterId ?? 0)}
            onChange={(e) => {
              const v = e.target.value;
              patch("alterId", v === "" ? "" : Number(v));
            }}
          />
        </Field>
        <Field label="cipher" error={errs.cipher}>
          <TSelect
            value={form.cipher}
            onChange={(v) => patch("cipher", v)}
            options={VMESS_CIPHERS}
            invalid={!!errs.cipher}
          />
        </Field>
        <Field label="network" error={errs.network}>
          <TSelect
            value={form.network}
            onChange={(v) => patch("network", v)}
            options={NETWORK_TYPES}
            invalid={!!errs.network}
          />
        </Field>
      </div>
      <TlsToggle form={form} patch={patch} errs={errs} />
    </div>
  );
}

function VlessFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <Field label="uuid" error={errs.uuid}>
        <TInput
          value={form.uuid}
          onChange={(v) => patch("uuid", v)}
          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          invalid={!!errs.uuid}
        />
      </Field>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="network" error={errs.network}>
          <TSelect
            value={form.network}
            onChange={(v) => patch("network", v)}
            options={NETWORK_TYPES}
            invalid={!!errs.network}
          />
        </Field>
        <Field label="flow (可选, 如 xtls-rprx-vision)">
          <TInput value={form.flow} onChange={(v) => patch("flow", v)} />
        </Field>
      </div>
      <TlsToggle form={form} patch={patch} errs={errs} />
    </div>
  );
}

function Hysteria2Fields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <Field label="password" error={errs.password}>
        <TInput
          value={form.password}
          onChange={(v) => patch("password", v)}
          invalid={!!errs.password}
        />
      </Field>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="sni (可选)">
          <TInput value={form.sni} onChange={(v) => patch("sni", v)} />
        </Field>
        <CheckboxField
          label="skip-cert-verify"
          checked={!!form["skip-cert-verify"]}
          onChange={(v) => patch("skip-cert-verify", v)}
        />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="up (可选, 如 50 mbps)">
          <TInput value={form.up} onChange={(v) => patch("up", v)} />
        </Field>
        <Field label="down (可选, 如 200 mbps)">
          <TInput value={form.down} onChange={(v) => patch("down", v)} />
        </Field>
      </div>
    </div>
  );
}

function HysteriaFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <Field label="auth-str" error={errs["auth-str"]}>
        <TInput
          value={form["auth-str"]}
          onChange={(v) => patch("auth-str", v)}
          invalid={!!errs["auth-str"]}
        />
      </Field>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Field label="up (Mbps)" error={errs.up}>
          <TInput
            type="number"
            value={form.up}
            onChange={(v) => patch("up", v)}
            invalid={!!errs.up}
          />
        </Field>
        <Field label="down (Mbps)" error={errs.down}>
          <TInput
            type="number"
            value={form.down}
            onChange={(v) => patch("down", v)}
            invalid={!!errs.down}
          />
        </Field>
        <Field label="protocol" error={errs.protocol}>
          <TSelect
            value={form.protocol}
            onChange={(v) => patch("protocol", v)}
            options={HYSTERIA_PROTOCOLS}
            invalid={!!errs.protocol}
          />
        </Field>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="sni (可选)">
          <TInput value={form.sni} onChange={(v) => patch("sni", v)} />
        </Field>
        <Field label="obfs (可选)">
          <TInput value={form.obfs} onChange={(v) => patch("obfs", v)} />
        </Field>
      </div>
      <CheckboxField
        label="skip-cert-verify"
        checked={!!form["skip-cert-verify"]}
        onChange={(v) => patch("skip-cert-verify", v)}
      />
    </div>
  );
}

function TuicFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="uuid" error={errs.uuid}>
          <TInput
            value={form.uuid}
            onChange={(v) => patch("uuid", v)}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            invalid={!!errs.uuid}
          />
        </Field>
        <Field label="password" error={errs.password}>
          <TInput
            value={form.password}
            onChange={(v) => patch("password", v)}
            invalid={!!errs.password}
          />
        </Field>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Field
          label="congestion-controller"
          error={errs["congestion-controller"]}
        >
          <TSelect
            value={form["congestion-controller"]}
            onChange={(v) => patch("congestion-controller", v)}
            options={TUIC_CC}
            invalid={!!errs["congestion-controller"]}
          />
        </Field>
        <Field label="udp-relay-mode" error={errs["udp-relay-mode"]}>
          <TSelect
            value={form["udp-relay-mode"]}
            onChange={(v) => patch("udp-relay-mode", v)}
            options={TUIC_UDP_MODES}
            invalid={!!errs["udp-relay-mode"]}
          />
        </Field>
        <Field label="version (4 / 5)" error={errs.version}>
          <Input
            type="number"
            min={4}
            max={5}
            value={form.version === "" ? "" : (form.version ?? 5)}
            onChange={(e) => {
              const v = e.target.value;
              patch("version", v === "" ? "" : Number(v));
            }}
          />
        </Field>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="sni (可选)">
          <TInput value={form.sni} onChange={(v) => patch("sni", v)} />
        </Field>
        <div className="space-y-2">
          <CheckboxField
            label="disable-sni"
            checked={!!form["disable-sni"]}
            onChange={(v) => patch("disable-sni", v)}
          />
          <CheckboxField
            label="skip-cert-verify"
            checked={!!form["skip-cert-verify"]}
            onChange={(v) => patch("skip-cert-verify", v)}
          />
        </div>
      </div>
    </div>
  );
}

function SnellFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3 grid grid-cols-1 md:grid-cols-2 gap-3">
      <Field label="psk (预共享密钥)" error={errs.psk}>
        <TInput
          value={form.psk}
          onChange={(v) => patch("psk", v)}
          invalid={!!errs.psk}
        />
      </Field>
      <Field label="version" error={errs.version}>
        <Input
          type="number"
          min={1}
          max={4}
          value={form.version === "" ? "" : (form.version ?? 4)}
          onChange={(e) => {
            const v = e.target.value;
            patch("version", v === "" ? "" : Number(v));
          }}
        />
      </Field>
    </div>
  );
}

function WireguardFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <Field label="private-key (本端私钥)" error={errs["private-key"]}>
        <TInput
          value={form["private-key"]}
          onChange={(v) => patch("private-key", v)}
          invalid={!!errs["private-key"]}
        />
      </Field>
      <Field label="public-key (对端公钥)" error={errs["public-key"]}>
        <TInput
          value={form["public-key"]}
          onChange={(v) => patch("public-key", v)}
          invalid={!!errs["public-key"]}
        />
      </Field>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="ip (本地隧道 IPv4)" error={errs.ip}>
          <TInput
            value={form.ip}
            onChange={(v) => patch("ip", v)}
            placeholder="10.0.0.2"
            invalid={!!errs.ip}
          />
        </Field>
        <Field label="ipv6 (可选)">
          <TInput value={form.ipv6} onChange={(v) => patch("ipv6", v)} />
        </Field>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="preshared-key (可选)">
          <TInput
            value={form["preshared-key"]}
            onChange={(v) => patch("preshared-key", v)}
          />
        </Field>
        <Field label="mtu (默认 1280)">
          <Input
            type="number"
            value={form.mtu === "" ? "" : (form.mtu ?? 1280)}
            onChange={(e) => {
              const v = e.target.value;
              patch("mtu", v === "" ? "" : Number(v));
            }}
          />
        </Field>
      </div>
    </div>
  );
}

function AnyTlsFields({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-3">
      <Field label="password" error={errs.password}>
        <TInput
          value={form.password}
          onChange={(v) => patch("password", v)}
          invalid={!!errs.password}
        />
      </Field>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="sni (可选)">
          <TInput value={form.sni} onChange={(v) => patch("sni", v)} />
        </Field>
        <Field label="client-fingerprint">
          <TInput
            value={form["client-fingerprint"]}
            onChange={(v) => patch("client-fingerprint", v)}
            placeholder="chrome / firefox / safari"
          />
        </Field>
      </div>
      <CheckboxField
        label="skip-cert-verify"
        checked={!!form["skip-cert-verify"]}
        onChange={(v) => patch("skip-cert-verify", v)}
      />
    </div>
  );
}

function UserPassTlsFields({ form, patch }: FieldProps) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="username (可选)">
          <TInput
            value={form.username}
            onChange={(v) => patch("username", v)}
          />
        </Field>
        <Field label="password (可选)">
          <TInput
            value={form.password}
            onChange={(v) => patch("password", v)}
          />
        </Field>
      </div>
      <div className="space-y-2">
        <CheckboxField
          label="tls"
          checked={!!form.tls}
          onChange={(v) => patch("tls", v)}
        />
        {form.tls && (
          <div className="pl-6">
            <CheckboxField
              label="skip-cert-verify"
              checked={!!form["skip-cert-verify"]}
              onChange={(v) => patch("skip-cert-verify", v)}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function TlsToggle({ form, patch, errs }: FieldProps) {
  return (
    <div className="space-y-2">
      <CheckboxField
        label="tls"
        checked={!!form.tls}
        onChange={(v) => patch("tls", v)}
      />
      {form.tls && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pl-6">
          <Field label="servername (SNI)" error={errs.servername}>
            <TInput
              value={form.servername}
              onChange={(v) => patch("servername", v)}
              invalid={!!errs.servername}
            />
          </Field>
          <CheckboxField
            label="skip-cert-verify"
            checked={!!form["skip-cert-verify"]}
            onChange={(v) => patch("skip-cert-verify", v)}
          />
        </div>
      )}
    </div>
  );
}

function CheckboxField({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-sm h-9">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      {label}
    </label>
  );
}
