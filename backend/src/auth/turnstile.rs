use serde::Deserialize;

use crate::error::{AppError, AppResult};

const VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

#[derive(Debug, Deserialize)]
struct TurnstileResponse {
    success: bool,
    #[serde(rename = "error-codes", default)]
    error_codes: Vec<String>,
}

/// 向 Cloudflare 校验 turnstile token. token 是前端 widget 拿到的 challenge response.
pub async fn verify(
    http: &reqwest::Client,
    secret: &str,
    token: &str,
    remote_ip: Option<&str>,
) -> AppResult<()> {
    let mut form: Vec<(&str, &str)> = vec![("secret", secret), ("response", token)];
    if let Some(ip) = remote_ip {
        form.push(("remoteip", ip));
    }
    let resp = http
        .post(VERIFY_URL)
        .form(&form)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("turnstile verify request failed: {e}")))?;
    let parsed: TurnstileResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("turnstile verify body invalid: {e}")))?;
    if !parsed.success {
        let codes = parsed.error_codes.join(",");
        return Err(AppError::BadRequest(format!(
            "验证码校验未通过: {codes}"
        )));
    }
    Ok(())
}
