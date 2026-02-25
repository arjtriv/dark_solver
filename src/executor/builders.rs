//! Builder-Direct RPC Integration
//!
//! Fan-out bundle submission to multiple block builders (BeaverBuild, Titan, Flashbots)
//! with zero public mempool exposure. Each builder implements the `BuilderClient` trait.

use crate::error::{Result, RpcError};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

/// Canonical bundle payload sent to all builders via `eth_sendBundle`.
#[derive(Debug, Clone, Serialize)]
pub struct BundlePayload {
    pub txs: Vec<String>,
    pub block_number: String,
    pub min_timestamp: u64,
    pub max_timestamp: u64,
    #[serde(rename = "revertingTxHashes")]
    pub reverting_tx_hashes: Vec<String>,
}

/// Response from a builder after bundle submission.
#[derive(Debug, Clone, Deserialize)]
pub struct BundleResponse {
    pub builder: String,
    pub accepted: bool,
    pub message: Option<String>,
    pub latency_us: Option<u64>,
}

/// Trait for any block builder endpoint.
#[async_trait]
pub trait BuilderClient: Send + Sync {
    fn name(&self) -> &str;
    async fn send_bundle(&self, bundle: &BundlePayload) -> Result<BundleResponse>;
    async fn secure_handshake(&self) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Concrete Builders
// ---------------------------------------------------------------------------

/// Generic JSON-RPC builder (works for Flashbots, BeaverBuild, Titan, etc.)
pub struct JsonRpcBuilder {
    name: String,
    url: String,
    client: Client,
}

const BUILDER_HTTP_TIMEOUT_MS: u64 = 5_000;

impl JsonRpcBuilder {
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        let client = match Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                eprintln!(
                    "[EXEC] Warning: failed to construct builder timeout HTTP client: {err}. Falling back to default client."
                );
                Client::new()
            }
        };
        Self {
            name: name.into(),
            url: url.into(),
            client,
        }
    }
}

#[async_trait]
impl BuilderClient for JsonRpcBuilder {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send_bundle(&self, bundle: &BundlePayload) -> Result<BundleResponse> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendBundle",
            "params": [bundle]
        });

        let resp = tokio::time::timeout(
            Duration::from_millis(BUILDER_HTTP_TIMEOUT_MS),
            self.client.post(&self.url).json(&payload).send(),
        )
        .await
        .map_err(|_| {
            RpcError::Transport(format!(
                "builder `{}` request timed out after {}ms",
                self.name, BUILDER_HTTP_TIMEOUT_MS
            ))
        })?
        .map_err(|err| RpcError::Transport(err.to_string()))?;

        let status = resp.status();
        let body =
            tokio::time::timeout(Duration::from_millis(BUILDER_HTTP_TIMEOUT_MS), resp.text())
                .await
                .map_err(|_| {
                    RpcError::Transport(format!(
                        "builder `{}` response read timed out after {}ms",
                        self.name, BUILDER_HTTP_TIMEOUT_MS
                    ))
                })?
                .map_err(|err| RpcError::Transport(err.to_string()))?;

        Ok(classify_bundle_submission_response(
            &self.name, status, &body,
        ))
    }

    async fn secure_handshake(&self) -> Result<()> {
        verify_private_transport_url(&self.url)?;
        probe_private_bundle_endpoint(&self.client, &self.url).await
    }
}

fn normalize_builder_url(raw: &str) -> (String, bool) {
    // Compatibility: treat `grpc://` and `grpcs://` as "direct-stream" private endpoints even when
    // the relay expects JSON-RPC over HTTP. This keeps configuration stable while avoiding extra
    // dependency weight in the engine.
    if let Some(rest) = raw.strip_prefix("grpc://") {
        return (format!("http://{}", rest), true);
    }
    if let Some(rest) = raw.strip_prefix("grpcs://") {
        return (format!("https://{}", rest), true);
    }
    (raw.to_string(), false)
}

// ---------------------------------------------------------------------------
// Multi-Builder Fan-Out
// ---------------------------------------------------------------------------

/// Submits bundles to ALL configured builders concurrently.
/// Returns on first acceptance or aggregated errors if all reject.
pub struct MultiBuilder {
    builders: Vec<Arc<dyn BuilderClient>>,
}

impl MultiBuilder {
    /// Create from a list of builder URLs.
    ///
    /// Known endpoints get named automatically:
    /// - `*beaverbuild*`  → "BeaverBuild"
    /// - `*titanbuilder*` → "Titan"
    /// - `*flashbots*`    → "Flashbots"
    /// - anything else    → "Builder-{index}"
    pub fn from_urls(urls: &[String]) -> Self {
        let builders: Vec<Arc<dyn BuilderClient>> = urls
            .iter()
            .enumerate()
            .map(|(i, url)| {
                let url_trim = url.trim();
                let (normalized_url, grpc_like) = normalize_builder_url(url_trim);

                let name = if url.contains("beaverbuild") {
                    "BeaverBuild".to_string()
                } else if url.contains("titanbuilder") {
                    "Titan".to_string()
                } else if url.contains("flashbots") {
                    "Flashbots".to_string()
                } else if grpc_like {
                    format!("DirectStream-{}", i)
                } else {
                    format!("Builder-{}", i)
                };
                Arc::new(JsonRpcBuilder::new(name, normalized_url)) as Arc<dyn BuilderClient>
            })
            .collect();

        Self { builders }
    }

    /// Fan-out: send bundle to all builders in parallel.
    /// Returns Vec of all responses (successes and failures).
    pub async fn send_bundle(&self, bundle: &BundlePayload) -> Vec<Result<BundleResponse>> {
        let mut tasks = Vec::with_capacity(self.builders.len());
        for builder in &self.builders {
            let builder = builder.clone();
            let bundle = bundle.clone();
            tasks.push(tokio::spawn(async move {
                let started = std::time::Instant::now();
                let mut response = builder.send_bundle(&bundle).await;
                if let Ok(ref mut resp) = response {
                    resp.latency_us = Some(started.elapsed().as_micros() as u64);
                }
                response
            }));
        }

        let mut results = Vec::with_capacity(tasks.len());
        for t in tasks {
            match t.await {
                Ok(res) => results.push(res),
                Err(err) => results.push(Err(RpcError::Transport(format!(
                    "builder dispatch join error: {err}"
                ))
                .into())),
            }
        }
        results
    }

    /// Ranked fan-out: dispatch builders in the order provided by `preferred_order`.
    /// Unknown builder names retain their original relative order after ranked builders.
    pub async fn send_bundle_ranked(
        &self,
        bundle: &BundlePayload,
        preferred_order: &[String],
    ) -> Vec<Result<BundleResponse>> {
        if preferred_order.is_empty() {
            return self.send_bundle(bundle).await;
        }

        let mut rank = HashMap::new();
        for (idx, name) in preferred_order.iter().enumerate() {
            rank.insert(name.to_ascii_lowercase(), idx);
        }

        let mut indices = (0..self.builders.len()).collect::<Vec<_>>();
        indices.sort_by_key(|idx| {
            let key = self.builders[*idx].name().to_ascii_lowercase();
            rank.get(&key).copied().unwrap_or(usize::MAX)
        });

        let mut results = Vec::with_capacity(self.builders.len());
        let mut tasks = Vec::with_capacity(indices.len());
        for idx in indices {
            let builder = self.builders[idx].clone();
            let bundle = bundle.clone();
            tasks.push(tokio::spawn(async move {
                let started = std::time::Instant::now();
                let mut response = builder.send_bundle(&bundle).await;
                if let Ok(ref mut resp) = response {
                    resp.latency_us = Some(started.elapsed().as_micros() as u64);
                }
                response
            }));
        }
        for t in tasks {
            match t.await {
                Ok(res) => results.push(res),
                Err(err) => results.push(Err(RpcError::Transport(format!(
                    "builder dispatch join error: {err}"
                ))
                .into())),
            }
        }
        results
    }

    /// Verifies each endpoint is private-relay safe before private submission.
    pub async fn secure_handshake(&self) -> Result<()> {
        let mut tasks = Vec::with_capacity(self.builders.len());
        for builder in &self.builders {
            let builder = builder.clone();
            tasks.push(tokio::spawn(async move {
                let name = builder.name().to_string();
                (name, builder.secure_handshake().await)
            }));
        }

        let mut failures = Vec::new();
        for t in tasks {
            match t.await {
                Ok((name, Ok(()))) => {
                    let _ = name;
                }
                Ok((name, Err(err))) => failures.push(format!("{}: {err}", name)),
                Err(err) => failures.push(format!("builder handshake join error: {err}")),
            }
        }

        if failures.is_empty() {
            return Ok(());
        }

        let mut summary = String::new();
        for (idx, failure) in failures.iter().enumerate() {
            if idx > 0 {
                let _ = write!(summary, "; ");
            }
            let _ = write!(summary, "{failure}");
        }
        Err(RpcError::BundleHandshakeRejected(format!(
            "secure handshake rejected builder endpoints (public mempool risk): {}",
            summary
        ))
        .into())
    }

    /// Returns true if any builder is configured.
    pub fn has_builders(&self) -> bool {
        !self.builders.is_empty()
    }

    /// Number of configured builders.
    pub fn num_builders(&self) -> usize {
        self.builders.len()
    }
}

// ---------------------------------------------------------------------------
// Default Builder Endpoints
// ---------------------------------------------------------------------------

/// Well-known builder endpoints for Ethereum Mainnet.
pub const DEFAULT_BUILDER_URLS: &[&str] = &[
    "https://relay.flashbots.net",
    "https://rpc.beaverbuild.org",
    "https://rpc.titanbuilder.xyz",
];

const PRIVATE_RELAY_HINTS: &[&str] = &[
    "flashbots",
    "relay",
    "builder",
    "beaverbuild",
    "titanbuilder",
    "bloxroute",
];

const PUBLIC_RPC_HINTS: &[&str] = &[
    "alchemy",
    "infura",
    "publicnode",
    "ankr",
    "quicknode",
    "cloudflare-eth",
    "llamarpc",
    "drpc",
];

fn host_contains_any(host: &str, hints: &[&str]) -> bool {
    hints.iter().any(|hint| host.contains(hint))
}

fn compact_log_snippet(body: &str) -> String {
    const MAX: usize = 160;
    let mut snippet = String::new();
    for (idx, ch) in body.chars().enumerate() {
        if idx >= MAX {
            break;
        }
        snippet.push(ch);
    }
    if body.chars().count() > MAX {
        snippet.push_str("...");
    }
    snippet
}

fn parse_jsonrpc_body(body: &str) -> std::result::Result<serde_json::Value, String> {
    serde_json::from_str(body).map_err(|err| err.to_string())
}

fn jsonrpc_error_summary(parsed: &serde_json::Value) -> Option<String> {
    let err = parsed.get("error")?;
    let code = err.get("code").and_then(|v| v.as_i64());
    let message = err
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown JSON-RPC error");
    Some(match code {
        Some(code) => format!("jsonrpc error code={} message={}", code, message),
        None => format!("jsonrpc error message={}", message),
    })
}

fn classify_bundle_submission_response(
    builder: &str,
    status: reqwest::StatusCode,
    body: &str,
) -> BundleResponse {
    if !status.is_success() {
        return BundleResponse {
            builder: builder.to_string(),
            accepted: false,
            message: Some(format!("HTTP {}: {}", status, compact_log_snippet(body))),
            latency_us: None,
        };
    }

    let parsed = match parse_jsonrpc_body(body) {
        Ok(v) => v,
        Err(err) => {
            return BundleResponse {
                builder: builder.to_string(),
                accepted: false,
                message: Some(format!(
                    "invalid JSON-RPC success body (decode error={}): {}",
                    err,
                    compact_log_snippet(body)
                )),
                latency_us: None,
            };
        }
    };

    if let Some(err) = jsonrpc_error_summary(&parsed) {
        return BundleResponse {
            builder: builder.to_string(),
            accepted: false,
            message: Some(err),
            latency_us: None,
        };
    }

    let accepted = match parsed.get("result") {
        Some(serde_json::Value::Null) | None => false,
        Some(serde_json::Value::Bool(v)) => *v,
        Some(serde_json::Value::String(v)) => !v.trim().is_empty(),
        Some(_) => true,
    };

    BundleResponse {
        builder: builder.to_string(),
        accepted,
        message: Some(compact_log_snippet(body)),
        latency_us: None,
    }
}

fn response_rejects_bundle_method(body: &str) -> bool {
    let lower_body = body.to_ascii_lowercase();
    if lower_body.contains("method not found") || lower_body.contains("unknown method") {
        return true;
    }

    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return false,
    };

    let Some(err) = parsed.get("error") else {
        return false;
    };
    if let Some(code) = err.get("code").and_then(|v| v.as_i64()) {
        if code == -32601 {
            return true;
        }
    }
    if let Some(message) = err.get("message").and_then(|v| v.as_str()) {
        let lower = message.to_ascii_lowercase();
        if lower.contains("method not found") || lower.contains("unknown method") {
            return true;
        }
    }
    false
}

/// Fast local guard that blocks obviously public-mempool RPC endpoints.
pub fn verify_private_transport_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).map_err(|err| RpcError::InvalidUrl {
        url: url.to_string(),
        reason: err.to_string(),
    })?;
    if parsed.scheme() != "https" {
        return Err(RpcError::PublicRpcEndpoint(format!(
            "builder endpoint `{url}` must use https to avoid plaintext mempool exposure"
        ))
        .into());
    }

    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if host.is_empty() {
        return Err(RpcError::InvalidUrl {
            url: url.to_string(),
            reason: "missing host".to_string(),
        }
        .into());
    }
    let appears_public = host_contains_any(&host, PUBLIC_RPC_HINTS);
    let appears_private = host_contains_any(&host, PRIVATE_RELAY_HINTS);
    if appears_public && !appears_private {
        return Err(RpcError::PublicRpcEndpoint(format!(
            "builder endpoint `{url}` looks like a public RPC host; refusing private submission relay"
        ))
        .into());
    }
    Ok(())
}

async fn probe_private_bundle_endpoint(client: &Client, url: &str) -> Result<()> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 999,
        "method": "eth_sendBundle",
        "params": [{
            "txs": [],
            "blockNumber": "0x0",
            "minTimestamp": 0,
            "maxTimestamp": 0,
            "revertingTxHashes": []
        }]
    });

    let resp = tokio::time::timeout(
        Duration::from_millis(BUILDER_HTTP_TIMEOUT_MS),
        client.post(url).json(&payload).send(),
    )
    .await
    .map_err(|_| {
        RpcError::Transport(format!(
            "bundle handshake request timed out for `{url}` after {}ms",
            BUILDER_HTTP_TIMEOUT_MS
        ))
    })?
    .map_err(|err| {
        RpcError::Transport(format!(
            "bundle handshake request failed for `{url}`: {err}"
        ))
    })?;
    let status = resp.status();
    let body = tokio::time::timeout(Duration::from_millis(BUILDER_HTTP_TIMEOUT_MS), resp.text())
        .await
        .map_err(|_| {
            RpcError::Transport(format!(
                "bundle handshake response read timed out for `{url}` after {}ms",
                BUILDER_HTTP_TIMEOUT_MS
            ))
        })?
        .map_err(|err| {
            RpcError::Transport(format!(
                "bundle handshake response read failed for `{url}`: {err}"
            ))
        })?;

    if !status.is_success() {
        return Err(RpcError::BundleHandshakeRejected(format!(
            "endpoint `{url}` failed handshake: HTTP {} body `{}`",
            status,
            compact_log_snippet(&body)
        ))
        .into());
    }

    let parsed = parse_jsonrpc_body(&body).map_err(|err| {
        RpcError::BundleHandshakeRejected(format!(
            "endpoint `{url}` returned malformed JSON-RPC during handshake: {} (decode error={})",
            compact_log_snippet(&body),
            err
        ))
    })?;

    if response_rejects_bundle_method(&body) {
        return Err(RpcError::BundleHandshakeRejected(format!(
            "endpoint `{url}` rejected eth_sendBundle (status {}, body `{}`)",
            status,
            compact_log_snippet(&body)
        ))
        .into());
    }

    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(RpcError::BundleHandshakeRejected(format!(
            "endpoint `{url}` returned 404 during bundle handshake (not a private builder endpoint)"
        ))
        .into());
    }

    if parsed.get("result").is_none() && parsed.get("error").is_none() {
        return Err(RpcError::BundleHandshakeRejected(format!(
            "endpoint `{url}` returned JSON-RPC body without `result`/`error`: `{}`",
            compact_log_snippet(&body)
        ))
        .into());
    }

    Ok(())
}

/// Create a MultiBuilder with the default endpoints.
pub fn default_multi_builder() -> MultiBuilder {
    let urls: Vec<String> = DEFAULT_BUILDER_URLS.iter().map(|s| s.to_string()).collect();
    MultiBuilder::from_urls(&urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_name_detection() {
        let urls = vec![
            "https://rpc.beaverbuild.org".to_string(),
            "https://rpc.titanbuilder.xyz".to_string(),
            "https://relay.flashbots.net".to_string(),
            "https://custom-builder.example.com".to_string(),
        ];
        let mb = MultiBuilder::from_urls(&urls);
        assert_eq!(mb.num_builders(), 4);
        assert!(mb.has_builders());
    }

    #[test]
    fn test_bundle_payload_serialization() {
        let payload = BundlePayload {
            txs: vec!["0xdead".to_string()],
            block_number: "0x1".to_string(),
            min_timestamp: 0,
            max_timestamp: 1000,
            reverting_tx_hashes: vec![],
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("revertingTxHashes"));
        assert!(json.contains("0xdead"));
    }

    #[test]
    fn test_verify_private_transport_url_rejects_plaintext_and_public_hosts() {
        let insecure = verify_private_transport_url("http://relay.flashbots.net");
        assert!(insecure.is_err());

        let public = verify_private_transport_url("https://eth-mainnet.g.alchemy.com/v2/demo");
        assert!(public.is_err());

        let private_ok = verify_private_transport_url("https://rpc.beaverbuild.org");
        assert!(private_ok.is_ok());
    }

    #[test]
    fn test_response_rejects_bundle_method_detection() {
        let method_not_found_json =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        assert!(response_rejects_bundle_method(method_not_found_json));

        let accepted_shape = r#"{"jsonrpc":"2.0","id":1,"result":"0xdeadbeef"}"#;
        assert!(!response_rejects_bundle_method(accepted_shape));
    }

    #[test]
    fn test_classify_bundle_submission_response_rejects_jsonrpc_error_on_http_200() {
        let body =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"bundle rejected"}}"#;
        let response =
            classify_bundle_submission_response("builder-x", reqwest::StatusCode::OK, body);
        assert!(!response.accepted);
        assert!(response
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("jsonrpc error"));
    }

    #[test]
    fn test_classify_bundle_submission_response_accepts_valid_result_shape() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":"Bundle Received"}"#;
        let response =
            classify_bundle_submission_response("builder-x", reqwest::StatusCode::OK, body);
        assert!(response.accepted);
    }
}
