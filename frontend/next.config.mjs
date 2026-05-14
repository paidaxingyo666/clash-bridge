/** @type {import('next').NextConfig} */
const backendTarget = process.env.BACKEND_INTERNAL_URL || "http://127.0.0.1:8080";

const nextConfig = {
  reactStrictMode: true,
  // 浏览器对前端域名发的 /api/* 和 /sub/* 请求, 由 Next server 反代到 backend
  // (容器内走 backend:8080, 本地 dev 走 127.0.0.1:8080).
  // 这样只需要暴露前端一个域名, 不需要 CORS, 订阅 URL 也走同域.
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${backendTarget}/api/:path*` },
      { source: "/sub/:path*", destination: `${backendTarget}/sub/:path*` },
    ];
  },
};

export default nextConfig;
