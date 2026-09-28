//! The HTTP rules every geodata and routing download shares: at most eight
//! redirects, each accepted only by the caller's URL rule, and a body capped
//! while it streams instead of after it arrived.
use reqwest::{redirect::Policy, Response, Url};

const MAX_REDIRECTS: usize = 8;

/// Follows redirects whose target `accept` allows, up to the shared limit.
pub(crate) fn redirects(accept: fn(&Url) -> bool) -> Policy {
    Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS || !accept(attempt.url()) {
            attempt.error("download_redirect_refused")
        } else {
            attempt.follow()
        }
    })
}

/// An HTTPS address without credentials, the rule for remote downloads.
pub(crate) fn secure_url(url: &Url) -> bool {
    url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
}

pub(crate) enum BodyError {
    TooLarge,
    Network(reqwest::Error),
}

/// Reads at most `limit` bytes; a larger declared or streamed body stops early.
pub(crate) async fn body(mut response: Response, limit: usize) -> Result<Vec<u8>, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(BodyError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(BodyError::Network)? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(BodyError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
