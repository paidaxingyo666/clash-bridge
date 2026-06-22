//! 渲染层: 把 [`InjectModel`](crate::generator::model::InjectModel) 渲染为各订阅格式。
//!
//! - [`ClashRenderer`](clash::ClashRenderer): 字节等价路径, clone upstream_root 后原地注入。
//! - [`SingboxRenderer`](singbox::SingboxRenderer): 从 InjectModel 从零构造 sing-box JSON。
//!
//! base64 / surge / quanx 这批 (批1 MVP) 不实现, 由 service 层返回"暂未实现"提示。

pub mod clash;
pub mod singbox;

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
/// 已实现: `clash.yaml` / `singbox.json`。
/// 未实现 (批2): `sub.txt` / `surge.conf` / `quanx.conf` → 返回 None, 由调用方区分处理。
pub fn pick_renderer(format: &str) -> Option<Box<dyn Renderer>> {
    match format {
        "clash.yaml" => Some(Box::new(clash::ClashRenderer)),
        "singbox.json" => Some(Box::new(singbox::SingboxRenderer)),
        _ => None,
    }
}

/// 已知但本批未实现的格式 (用于给出"批2 再支持"的明确提示, 区别于未知格式 404)。
pub fn is_known_unimplemented_format(format: &str) -> bool {
    matches!(format, "sub.txt" | "surge.conf" | "quanx.conf")
}
