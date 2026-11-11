use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use colored::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
#[allow(dead_code)]
pub struct GatewayState {
    pub api_key: String,
    pub upstream_model: String,
    pub port: u16,
    pub client: reqwest::Client,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChatCompletionRequest {
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
}

#[derive(Debug, Serialize)]
pub struct ChatChoice {
    pub index: usize,
    pub message: ChatMessage,
    pub finish_reason: String,
}

pub async fn run_gateway(
    port: u16,
    upstream_model: Option<String>,
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
        port,
        client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/", get(health_check))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/models", get(list_models))
        .layer(CorsLayer::permissive())
        .with_state(state);

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
    println!(
        "{:<24}: Active (Blocking hostile probes & shell injection)",
        "Sentinel Firewall".bold()
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

async fn chat_completions(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<ChatCompletionRequest>,
) -> Result<Json<ChatCompletionResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 1. Nether Ward Sentinel Firewall: Inspect user messages for threat patterns
    let combined_user_text: String = req
        .messages
        .iter()
        .filter(|m| m.role == "user")
        .map(|m| m.content.clone())
        .collect::<Vec<_>>()
        .join("\n");

    let report = crate::threat::analyze_payload(combined_user_text.as_bytes());
    if report.severity == crate::threat::ThreatSeverity::Critical {
        eprintln!(
            "{} Blocked CRITICAL threat payload in gateway: {:?}",
            "NETHER WARD SENTINEL:".red().bold(),
            report.detected_indicators
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": {
                    "message": "Nether Ward Sentinel: Request blocked by security firewall. Hostile command or injection pattern detected.",
                    "type": "security_policy_violation",
                    "code": "nether_ward_threat_blocked",
                    "detected_indicators": report.detected_indicators,
                    "entropy": report.entropy
                }
            })),
        ));
    }

    // 2. Map messages to Gemini format
    let target_model = req.model.unwrap_or_else(|| state.upstream_model.clone());
    let mut contents = Vec::new();
    let mut system_instruction = None;

    for msg in req.messages {
        if msg.role == "system" {
            system_instruction = Some(serde_json::json!({
                "parts": [{ "text": msg.content }]
            }));
        } else {
            let role = if msg.role == "assistant" {
                "model"
            } else {
                "user"
            };
            contents.push(serde_json::json!({
                "role": role,
                "parts": [{ "text": msg.content }]
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

    let resp = state.client.post(&url)
        .json(&gemini_payload)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": { "message": format!("Upstream call failed: {e}") } })),
            )
        })?;

    if !resp.status().is_success() {
        let err_text = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(
                serde_json::json!({ "error": { "message": format!("Upstream Gemini error: {err_text}") } }),
            ),
        ));
    }

    let gemini_json: serde_json::Value = resp.json().await.unwrap_or_default();
    let reply_text = gemini_json["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();

    Ok(Json(ChatCompletionResponse {
        id: format!("chatcmpl-{}", chrono::Utc::now().timestamp_millis()),
        object: "chat.completion".to_string(),
        created: chrono::Utc::now().timestamp() as u64,
        model: target_model,
        choices: vec![ChatChoice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: reply_text,
            },
            finish_reason: "stop".to_string(),
        }],
    }))
}
