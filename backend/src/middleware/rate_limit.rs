use axum::http::Request;
use tower_governor::key_extractor::KeyExtractor;

/// 从请求头取真实客户端 IP. 优先 cf-connecting-ip (Cloudflare Tunnel / proxy 必带),
/// fallback x-forwarded-for, 再 fallback x-real-ip.
#[derive(Clone, Debug)]
pub struct CfConnectingIpExtractor;

impl KeyExtractor for CfConnectingIpExtractor {
    type Key = String;

    fn extract<B>(
        &self,
        req: &Request<B>,
    ) -> Result<Self::Key, tower_governor::GovernorError> {
        let h = req.headers();
        let ip = h
            .get("cf-connecting-ip")
            .or_else(|| h.get("x-forwarded-for"))
            .or_else(|| h.get("x-real-ip"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        ip.ok_or(tower_governor::GovernorError::UnableToExtractKey)
    }
}
