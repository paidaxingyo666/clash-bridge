//! 渲染层: 把 [`InjectModel`](crate::generator::model::InjectModel) 渲染为各订阅格式。
//!
//! - [`ClashRenderer`](clash::ClashRenderer): 字节等价路径, clone upstream_root 后原地注入。
//! - [`SingboxRenderer`](singbox::SingboxRenderer): 从 InjectModel 从零构造 sing-box JSON。
//! - [`Base64Renderer`](base64::Base64Renderer): 上游裸节点 → URI 列表整体 base64。
//! - [`SurgeRenderer`](surge::SurgeRenderer): Surge `.conf` ini。
//! - [`QuanXRenderer`](quanx::QuanXRenderer): Quantumult X `.conf`。
//!
//! Clash / sing-box 支持固定出口链路 (relay); base64 / surge / quanx 不支持
//! (`supports_relay_chain()=false`), 含链路 profile 由 service 层返回 415。

pub mod base64;
pub mod clash;
pub mod quanx;
pub mod singbox;
pub mod surge;
pub mod uri_encode;

use crate::error::AppResult;
use crate::generator::model::InjectModel;

/// 一次渲染产物。
#[derive(Debug, Clone)]
pub struct RenderedSub {
    pub body: String,
    pub content_type: &'static str,
    pub filename_ext: &'static str,
    /// 渲染时被跳过的协议 / 节点说明 (如 sing-box 不支持的 ssr / tuic-v4)。
    /// handler 可据此加 `X-Skipped-Protocols` 头, 避免静默丢节点。
    pub skipped: Vec<String>,
}

impl RenderedSub {
    pub fn new(body: String, content_type: &'static str, filename_ext: &'static str) -> Self {
        Self { body, content_type, filename_ext, skipped: Vec::new() }
    }
}

pub trait Renderer: Send + Sync {
    fn render(&self, model: &InjectModel) -> AppResult<RenderedSub>;
    /// 该格式能否表达固定出口链路 (dialer-proxy / detour)。
    fn supports_relay_chain(&self) -> bool;
    fn format_id(&self) -> &'static str;
}

/// 按 URL 末段 format 选择渲染器。
/// 已实现: `clash.yaml` / `singbox.json` / `sub.txt` / `surge.conf` / `quanx.conf`。
/// 未知格式返回 None (调用方 404)。
pub fn pick_renderer(format: &str) -> Option<Box<dyn Renderer>> {
    match format {
        "clash.yaml" => Some(Box::new(clash::ClashRenderer)),
        "singbox.json" => Some(Box::new(singbox::SingboxRenderer)),
        "sub.txt" => Some(Box::new(base64::Base64Renderer)),
        "surge.conf" => Some(Box::new(surge::SurgeRenderer)),
        "quanx.conf" => Some(Box::new(quanx::QuanXRenderer)),
        _ => None,
    }
}
