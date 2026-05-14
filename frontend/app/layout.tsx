import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Clash Bridge",
  description: "跳板节点订阅生成器",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh">
      <body>{children}</body>
    </html>
  );
}
