//! Downloading a subscription: bounded HTTP, redirects, cancellation and usage headers.
use super::*;

#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
}
impl Usage {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let fields: HashMap<_, _> = value
            .split(';')
            .filter_map(|part| part.trim().split_once('='))
            .filter_map(|(key, value)| {
                value
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n <= 9_007_199_254_740_991)
                    .map(|n| (key.trim().to_ascii_lowercase(), n))
            })
            .collect();
        let result = Self {
            upload: fields.get("upload").copied(),
            download: fields.get("download").copied(),
            total: fields.get("total").copied(),
            expire: fields.get("expire").copied(),
        };
        (result != Self::default()).then_some(result)
    }
}
#[derive(Serialize)]
pub struct Download {
    pub metadata: Metadata,
    pub body: String,
    pub usage: Option<Usage>,
}
#[derive(Default)]
pub struct Downloads {
    pub(crate) active: Mutex<HashMap<String, watch::Sender<bool>>>,
}
impl Downloads {
    pub async fn cancel(&self, id: &str) {
        if let Some(sender) = self.active.lock().await.get(id) {
            let _ = sender.send(true);
        }
    }
    pub async fn fetch(
        &self,
        id: &str,
        settings: &Settings,
        proxy: Option<&str>,
    ) -> Result<Download, String> {
        if uuid::Uuid::parse_str(id).is_err() {
            return Err("invalid_download_id".into());
        }
        settings.validate()?;
        let (sender, mut cancelled) = watch::channel(false);
        {
            let mut active = self.active.lock().await;
            if active.contains_key(id) || active.len() >= 4 {
                return Err("subscription_download_busy".into());
            }
            active.insert(id.into(), sender);
        }
        let result = tokio::select! {
            biased;
            _ = cancelled.changed() => Err("subscription_cancelled".into()),
            result = tokio::time::timeout(settings.timeout(), fetch(settings, proxy)) => result.unwrap_or_else(|_| Err("subscription_timeout".into())),
        };
        self.active.lock().await.remove(id);
        result
    }
}
pub(crate) async fn fetch(settings: &Settings, proxy: Option<&str>) -> Result<Download, String> {
    let mut url = valid_url(&settings.url)?;
    let original_origin = url.origin();
    let mut client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(settings.allow_insecure)
        .timeout(settings.timeout())
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(10))
        .user_agent(user_agent());
    if settings.via_proxy {
        let proxy = proxy.ok_or("subscription_proxy_unavailable")?;
        client =
            client.proxy(reqwest::Proxy::all(proxy).map_err(|_| "subscription_proxy_unavailable")?);
    }
    let client = client.build().map_err(|_| "subscription_network_error")?;
    // The User-Agent names the client, not the account: unlike the custom
    // headers it follows a redirect to another origin.
    let user_agent =
        HeaderValue::from_str(&settings.user_agent).map_err(|_| "invalid_subscription_headers")?;
    let mut headers = HeaderMap::new();
    for (key, value) in &settings.headers {
        headers.insert(
            HeaderName::from_bytes(key.as_bytes()).map_err(|_| "invalid_subscription_headers")?,
            HeaderValue::from_str(value).map_err(|_| "invalid_subscription_headers")?,
        );
    }
    let mut forward_headers = true;
    for hop in 0..=5 {
        let mut request = client
            .get(url.clone())
            .header(reqwest::header::USER_AGENT, user_agent.clone());
        if forward_headers {
            request = request.headers(headers.clone());
        }
        let mut response = request.send().await.map_err(network_error)?;
        if response.status().is_redirection() {
            if hop == 5 {
                return Err("subscription_redirect_error".into());
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or("subscription_redirect_error")?;
            let next = url
                .join(location)
                .map_err(|_| "subscription_redirect_error")?;
            valid_url(next.as_str())?;
            if url.scheme() == "https" && next.scheme() != "https" {
                return Err("subscription_redirect_error".into());
            }
            forward_headers &= next.origin() == original_origin;
            url = next;
            continue;
        }
        // A partial response may be a syntactically valid prefix of a subscription.
        // It must never become a removal plan for the missing remainder.
        if !response.status().is_success()
            || response.status() == reqwest::StatusCode::PARTIAL_CONTENT
        {
            let status = response.status().as_u16();
            return Err(if HTTP_STATUSES.contains(&status) {
                format!("subscription_http_{status}")
            } else {
                "subscription_http_error".into()
            });
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_BYTES as u64)
        {
            return Err("subscription_too_large".into());
        }
        let headers = response.headers().clone();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(network_error)? {
            if bytes.len() + chunk.len() > MAX_BYTES {
                return Err("subscription_too_large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut body = String::from_utf8(bytes).map_err(|_| "subscription_invalid_text")?;
        let (metadata, usage) = metadata::extract(&headers, &mut body);
        if body.trim().is_empty() {
            return Err("subscription_empty".into());
        }
        return Ok(Download {
            body,
            usage,
            metadata,
        });
    }
    Err("subscription_redirect_error".into())
}
pub(crate) fn network_error(error: reqwest::Error) -> String {
    // reqwest error strings can contain the complete URL, including subscription tokens.
    if error.is_timeout() {
        "subscription_timeout"
    } else {
        "subscription_network_error"
    }
    .into()
}
