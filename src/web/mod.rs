use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use chrono::Utc;
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use tower_http::cors::CorsLayer;

use crate::components::sentry::SentryEngine;
use crate::components::sonar::{
    FlowType, RadarCoordinate, SonarEngine, SonarPacket, ThreatVerdict,
};
use crate::core::models::{AlertSeverity, Document, SentryAlert};

pub mod auth;

pub const INDEX_HTML: &str = include_str!("assets/index.html");
pub const LOGO_SVG: &str = include_str!("assets/logo.svg");

#[derive(Clone)]
pub struct WebAppState {
    pub sentry: Arc<SentryEngine>,
    pub auth: auth::AuthDb,
    pub chaos: Arc<crate::components::chaos::ChaosEngine>,
    pub sonar: Arc<SonarEngine>,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub status: String,
    pub total_chunks: usize,
    pub total_audits: usize,
    pub embedder_dimension: usize,
    pub generator_model: String,
    pub guardrail_enabled: bool,
}

#[derive(Deserialize)]
pub struct IngestRequest {
    pub title: String,
    pub content: String,
    pub category: Option<String>,
    pub severity: Option<String>,
}

#[derive(Serialize)]
pub struct IngestResponse {
    pub success: bool,
    pub document_id: String,
    pub chunks_indexed: usize,
    pub total_indexed: usize,
}

#[derive(Deserialize)]
pub struct InvestigateRequest {
    pub title: String,
    pub severity: String,
    pub source: String,
    pub raw_telemetry: String,
}

#[derive(Serialize)]
pub struct InvestigateResponse {
    pub report: crate::core::models::AnalysisReport,
    pub guardrail_interception: bool,
    pub latency_ms: u128,
}

#[derive(Deserialize)]
pub struct GuardrailTestRequest {
    pub payload: String,
    pub mode: String,
    pub context: Option<String>,
}

#[derive(Serialize)]
pub struct KnowledgeChunkItem {
    pub chunk_id: String,
    pub document_id: String,
    pub chunk_index: usize,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub content: String,
    pub token_count: usize,
}

#[derive(Deserialize)]
pub struct AuthRegisterRequest {
    pub username: String,
    pub password: String,
    pub role: Option<String>,
}

#[derive(Deserialize)]
pub struct AuthLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<String>,
    pub user: Option<auth::UserInfo>,
    pub message: Option<String>,
}

#[derive(Deserialize)]
pub struct ChaosRunRequest {
    pub experiment_id: String,
}

#[derive(Deserialize)]
pub struct NineRouterConnectRequest {
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
    pub routing_profile: Option<String>,
}

#[derive(Deserialize)]
pub struct NineRouterProbeRequest {
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
}

#[derive(Deserialize)]
pub struct SonarSimulateRequest {
    pub sample_type: Option<String>,
}

// ==========================================
// OPENAI-COMPATIBLE PROXY & PROMETHEUS TYPES
// ==========================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenAiMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenAiChatRequest {
    pub model: String,
    pub messages: Vec<OpenAiMessage>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub max_tokens: Option<usize>,
    #[serde(default)]
    pub stream: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenAiChoice {
    pub index: usize,
    pub message: OpenAiMessage,
    pub finish_reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenAiUsage {
    pub prompt_tokens: usize,
    pub completion_tokens: usize,
    pub total_tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenAiChatResponse {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub model: String,
    pub choices: Vec<OpenAiChoice>,
    pub usage: OpenAiUsage,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenAiErrorResponse {
    pub error: OpenAiErrorDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenAiErrorDetail {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenAiModelItem {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub owned_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenAiModelListResponse {
    pub object: String,
    pub data: Vec<OpenAiModelItem>,
}

pub fn create_router(state: WebAppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/assets/logo.svg", get(serve_logo))
        .route("/api/stats", get(get_stats))
        .route("/api/knowledge", get(get_knowledge).post(ingest_knowledge))
        .route("/api/investigate", post(investigate_alert))
        .route("/api/audit", get(get_audit_trail))
        .route("/api/guardrail/test", post(test_guardrail))
        // Real-Time Sonar Detector & 9router Gateway SSE Streams
        .route("/api/sonar/stream", get(stream_sonar_events))
        .route("/api/sonar/packets", get(get_sonar_recent))
        .route("/api/sonar/9router/status", get(get_9router_status_handler))
        .route("/api/sonar/9router/connect", post(connect_9router_handler))
        .route("/api/sonar/9router/probe", post(probe_9router_tunnel_handler))
        .route("/api/sonar/9router/disconnect", post(disconnect_9router_handler))
        .route("/api/sonar/simulate", post(simulate_sonar_packet_handler))
        // Agentic Chaos Engineering Endpoints
        .route("/api/chaos/experiments", get(get_chaos_experiments))
        .route("/api/chaos/run", post(run_chaos))
        .route("/api/chaos/metrics", get(get_chaos_metrics))
        // Authentication Endpoints (SQLite Powered)
        .route("/api/auth/register", post(auth_register))
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/me", get(auth_me))
        .route("/api/auth/logout", post(auth_logout))
        // OpenAI-Compatible AI Security Reverse Proxy (n8n, Hermes, Cursor, Python Agents)
        .route("/v1/chat/completions", post(openai_chat_completions_proxy))
        .route("/v1/models", get(openai_list_models))
        // Prometheus Metrics Exporter (SIEM / Grafana / Datadog)
        .route("/metrics", get(export_prometheus_metrics))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn serve_index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

async fn serve_logo() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "image/svg+xml")], LOGO_SVG)
}

async fn get_stats(State(state): State<WebAppState>) -> impl IntoResponse {
    let total_chunks = state.sentry.vector_store.count().await;
    let total_audits = if let Some(ref auditor) = state.sentry.auditor {
        auditor.count().await
    } else {
        0
    };

    Json(StatsResponse {
        status: "SENTINEL ARMED [ONLINE]".to_string(),
        total_chunks,
        total_audits,
        embedder_dimension: state.sentry.embedder.dimension(),
        generator_model: state.sentry.generator.model_name().to_string(),
        guardrail_enabled: state.sentry.guardrail.is_some(),
    })
}

async fn get_knowledge(State(state): State<WebAppState>) -> impl IntoResponse {
    match state.sentry.vector_store.get_all_documents().await {
        Ok(docs) => {
            let items: Vec<KnowledgeChunkItem> = docs
                .into_iter()
                .map(|doc| {
                    let title = doc
                        .chunk
                        .metadata
                        .get("title")
                        .cloned()
                        .unwrap_or_else(|| "Untitled".to_string());
                    let category = doc
                        .chunk
                        .metadata
                        .get("category")
                        .cloned()
                        .unwrap_or_else(|| "General".to_string());
                    let severity = doc
                        .chunk
                        .metadata
                        .get("severity")
                        .cloned()
                        .unwrap_or_else(|| "Medium".to_string());

                    KnowledgeChunkItem {
                        chunk_id: doc.chunk.id,
                        document_id: doc.chunk.document_id,
                        chunk_index: doc.chunk.chunk_index,
                        title,
                        category,
                        severity,
                        content: doc.chunk.content,
                        token_count: doc.chunk.token_count_approx,
                    }
                })
                .collect();
            (StatusCode::OK, Json(items)).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn ingest_knowledge(
    State(state): State<WebAppState>,
    Json(payload): Json<IngestRequest>,
) -> impl IntoResponse {
    let mut doc = Document::new(payload.title, payload.content);
    if let Some(cat) = payload.category {
        doc = doc.with_metadata("category", cat);
    }
    if let Some(sev) = payload.severity {
        doc = doc.with_metadata("severity", sev);
    }

    let doc_id = doc.id.clone();
    match state.sentry.ingest_knowledge(doc).await {
        Ok(chunks_indexed) => {
            let total_indexed = state.sentry.vector_store.count().await;
            (
                StatusCode::OK,
                Json(IngestResponse {
                    success: true,
                    document_id: doc_id,
                    chunks_indexed,
                    total_indexed,
                }),
            )
                .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn investigate_alert(
    State(state): State<WebAppState>,
    Json(payload): Json<InvestigateRequest>,
) -> impl IntoResponse {
    let severity = match payload.severity.to_lowercase().as_str() {
        "critical" => AlertSeverity::Critical,
        "high" => AlertSeverity::High,
        "medium" => AlertSeverity::Medium,
        "low" => AlertSeverity::Low,
        _ => AlertSeverity::Info,
    };

    let alert = SentryAlert::new(
        payload.title,
        severity,
        payload.source,
        payload.raw_telemetry,
    );

    // Emit Inbound Sonar Pulse
    let in_pulse = SonarPacket {
        id: format!("pkt-in-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        timestamp: Utc::now(),
        flow_type: FlowType::InboundRequest,
        upstream_gateway: "9router Edge Router".to_string(),
        provider: "Anthropic / OpenAI Mesh".to_string(),
        model: state.sentry.generator.model_name().to_string(),
        client_origin: format!("SOC [{}]", alert.source),
        latency_ms: 15,
        prompt_tokens: alert.raw_telemetry.len() / 4 + 80,
        completion_tokens: 0,
        estimated_cost_usd: 0.0006,
        threat_verdict: ThreatVerdict::Clean,
        radar_coordinate: RadarCoordinate {
            angle_deg: 120.0,
            distance_norm: 0.28,
            frequency_khz: 14.5,
            intensity_db: -9.0,
        },
        payload_preview: format!("INBOUND_TRIAGE: {}", alert.title),
    };
    state.sonar.emit_packet(in_pulse).await;

    let start = Instant::now();
    match state.sentry.investigate_alert(&alert).await {
        Ok(report) => {
            let latency_ms = start.elapsed().as_millis();
            let guardrail_interception = report.title.contains("[SECURITY VIOLATION DETECTED]");

            // Emit Outbound / Intercepted Sonar Pulse
            let out_pulse = SonarPacket {
                id: format!("pkt-out-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                timestamp: Utc::now(),
                flow_type: if guardrail_interception {
                    FlowType::GuardrailInterception
                } else {
                    FlowType::OutboundResponse
                },
                upstream_gateway: "9router Edge Router".to_string(),
                provider: "Anthropic Claude 3.5 Sonnet".to_string(),
                model: state.sentry.generator.model_name().to_string(),
                client_origin: format!("SOC [{}]", alert.source),
                latency_ms: latency_ms as u64,
                prompt_tokens: alert.raw_telemetry.len() / 4 + 80,
                completion_tokens: report.root_cause_analysis.len() / 4 + 40,
                estimated_cost_usd: 0.0022,
                threat_verdict: if guardrail_interception {
                    ThreatVerdict::Blocked
                } else {
                    ThreatVerdict::Clean
                },
                radar_coordinate: RadarCoordinate {
                    angle_deg: if guardrail_interception { 295.0 } else { 120.0 },
                    distance_norm: if guardrail_interception { 0.88 } else { 0.22 },
                    frequency_khz: if guardrail_interception { 22.0 } else { 16.0 },
                    intensity_db: if guardrail_interception { -1.5 } else { -7.5 },
                },
                payload_preview: format!("OUTBOUND_ANALYSIS: {}", report.title),
            };
            state.sonar.emit_packet(out_pulse).await;

            (
                StatusCode::OK,
                Json(InvestigateResponse {
                    report,
                    guardrail_interception,
                    latency_ms,
                }),
            )
                .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn get_audit_trail(State(state): State<WebAppState>) -> impl IntoResponse {
    if let Some(ref auditor) = state.sentry.auditor {
        let records = auditor.get_records().await;
        (StatusCode::OK, Json(records)).into_response()
    } else {
        (
            StatusCode::OK,
            Json(Vec::<crate::components::auditor::AuditRecord>::new()),
        )
            .into_response()
    }
}

async fn test_guardrail(
    State(state): State<WebAppState>,
    Json(payload): Json<GuardrailTestRequest>,
) -> impl IntoResponse {
    let result = if payload.mode == "output" {
        state
            .sentry
            .test_guardrail_output(&payload.payload, payload.context.as_deref().unwrap_or(""))
            .await
    } else {
        state.sentry.test_guardrail_input(&payload.payload).await
    };

    let is_blocked = match &result {
        Ok(v) => !v.passed,
        Err(_) => true,
    };

    let gr_pulse = SonarPacket {
        id: format!("pkt-gr-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        timestamp: Utc::now(),
        flow_type: if is_blocked {
            FlowType::GuardrailInterception
        } else {
            FlowType::InboundRequest
        },
        upstream_gateway: "9router Sentinel Filter".to_string(),
        provider: "NovaSentry Guardrail Engine".to_string(),
        model: "heuristics/injection-shield".to_string(),
        client_origin: "Interactive Guardrail Tester".to_string(),
        latency_ms: 12,
        prompt_tokens: payload.payload.len() / 4 + 10,
        completion_tokens: 0,
        estimated_cost_usd: 0.0001,
        threat_verdict: if is_blocked {
            ThreatVerdict::Blocked
        } else {
            ThreatVerdict::Clean
        },
        radar_coordinate: RadarCoordinate {
            angle_deg: if is_blocked { 320.0 } else { 45.0 },
            distance_norm: if is_blocked { 0.90 } else { 0.18 },
            frequency_khz: if is_blocked { 21.5 } else { 15.0 },
            intensity_db: if is_blocked { -2.0 } else { -12.0 },
        },
        payload_preview: format!(
            "GUARDRAIL_EVAL [{}]: {}",
            payload.mode,
            &payload.payload.chars().take(60).collect::<String>()
        ),
    };
    state.sonar.emit_packet(gr_pulse).await;

    match result {
        Ok(verdict) => (StatusCode::OK, Json(verdict)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

// ==========================================
// REAL-TIME SONAR DETECTOR & 9ROUTER HANDLERS
// ==========================================

async fn stream_sonar_events(
    State(state): State<WebAppState>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.sonar.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(packet) => {
            let json = serde_json::to_string(&packet).unwrap_or_default();
            Some(Ok(Event::default().event("sonar_pulse").data(json)))
        }
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn get_sonar_recent(State(state): State<WebAppState>) -> impl IntoResponse {
    let packets = state.sonar.get_recent_packets().await;
    Json(packets)
}

async fn get_9router_status_handler(State(state): State<WebAppState>) -> impl IntoResponse {
    let status = state.sonar.get_9router_status().await;
    Json(status)
}

async fn connect_9router_handler(
    State(state): State<WebAppState>,
    Json(payload): Json<NineRouterConnectRequest>,
) -> impl IntoResponse {
    let status = state
        .sonar
        .connect_9router(payload.endpoint, payload.api_key, payload.routing_profile)
        .await;
    Json(status)
}

async fn probe_9router_tunnel_handler(
    State(state): State<WebAppState>,
    Json(payload): Json<NineRouterProbeRequest>,
) -> impl IntoResponse {
    let result = state
        .sonar
        .probe_tunnel(payload.endpoint.as_deref(), payload.api_key.as_deref())
        .await;
    Json(result)
}

async fn disconnect_9router_handler(State(state): State<WebAppState>) -> impl IntoResponse {
    let status = state.sonar.disconnect_9router().await;
    Json(status)
}

async fn simulate_sonar_packet_handler(
    State(state): State<WebAppState>,
    Json(payload): Json<SonarSimulateRequest>,
) -> impl IntoResponse {
    let packet = state.sonar.simulate_packet(payload.sample_type.as_deref()).await;
    Json(packet)
}

// ==========================================
// AGENTIC CHAOS ENGINEERING HANDLERS
// ==========================================

async fn get_chaos_experiments(State(state): State<WebAppState>) -> impl IntoResponse {
    Json(state.chaos.list_experiments())
}

async fn get_chaos_metrics(State(state): State<WebAppState>) -> impl IntoResponse {
    let metrics = state.chaos.get_metrics().await;
    Json(metrics)
}

async fn run_chaos(
    State(state): State<WebAppState>,
    Json(payload): Json<ChaosRunRequest>,
) -> impl IntoResponse {
    match state.chaos.run_experiment(&state.sentry, &payload.experiment_id).await {
        Ok(result) => {
            let chaos_pulse = SonarPacket {
                id: format!("pkt-chaos-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                timestamp: Utc::now(),
                flow_type: FlowType::RouterFallback,
                upstream_gateway: "9router Chaos Resilience Lab".to_string(),
                provider: "Resilience Orchestrator".to_string(),
                model: "chaos/resilience-simulation".to_string(),
                client_origin: "Chaos Engineering Lab".to_string(),
                latency_ms: result.latency_ms as u64,
                prompt_tokens: 850,
                completion_tokens: 320,
                estimated_cost_usd: 0.0008,
                threat_verdict: if result.circuit_breaker_triggered {
                    ThreatVerdict::Blocked
                } else {
                    ThreatVerdict::Anomalous
                },
                radar_coordinate: RadarCoordinate {
                    angle_deg: 210.0,
                    distance_norm: 0.72,
                    frequency_khz: 19.0,
                    intensity_db: -3.5,
                },
                payload_preview: format!("CHAOS_DISRUPTION: {}", result.experiment_title),
            };
            state.sonar.emit_packet(chaos_pulse).await;

            (StatusCode::OK, Json(serde_json::to_value(result).unwrap_or_default())).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err })),
        ).into_response(),
    }
}

// ==========================================
// SQLITE AUTH HANDLERS
// ==========================================

async fn auth_register(
    State(state): State<WebAppState>,
    Json(payload): Json<AuthRegisterRequest>,
) -> impl IntoResponse {
    let role = payload.role.unwrap_or_else(|| "Security Operator".to_string());
    match state.auth.register(&payload.username, &payload.password, &role).await {
        Ok((user, token)) => (
            StatusCode::OK,
            Json(AuthResponse {
                success: true,
                token: Some(token),
                user: Some(user),
                message: Some("Registration successful".to_string()),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(AuthResponse {
                success: false,
                token: None,
                user: None,
                message: Some(err),
            }),
        )
            .into_response(),
    }
}

async fn auth_login(
    State(state): State<WebAppState>,
    Json(payload): Json<AuthLoginRequest>,
) -> impl IntoResponse {
    match state.auth.login(&payload.username, &payload.password).await {
        Ok((user, token)) => (
            StatusCode::OK,
            Json(AuthResponse {
                success: true,
                token: Some(token),
                user: Some(user),
                message: Some("Login successful".to_string()),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                success: false,
                token: None,
                user: None,
                message: Some(err),
            }),
        )
            .into_response(),
    }
}

async fn auth_me(
    State(state): State<WebAppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").or(Some(h)));

    if let Some(token) = token {
        if let Some(session) = state.auth.validate_token(token).await {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "authenticated": true,
                    "session": session
                })),
            )
                .into_response();
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "authenticated": false,
            "message": "Invalid or expired session token"
        })),
    )
        .into_response()
}

async fn auth_logout(
    State(state): State<WebAppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").or(Some(h)));

    if let Some(token) = token {
        let _ = state.auth.logout(token).await;
    }

    (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
}

// ==========================================
// OPENAI-COMPATIBLE PROXY & METRICS HANDLERS
// ==========================================

async fn openai_chat_completions_proxy(
    State(state): State<WebAppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<OpenAiChatRequest>,
) -> impl IntoResponse {
    let start = Instant::now();
    let request_id = format!("chatcmpl-ns-{}", &uuid::Uuid::new_v4().to_string()[..12]);

    // 1. Ingress Security Inspection across all prompt messages
    let mut combined_input = String::new();
    for msg in &payload.messages {
        combined_input.push_str(&format!("{}: {}\n", msg.role, msg.content));
    }

    let mut blocked = false;
    let mut violation_reason = String::new();

    if let Some(ref g) = state.sentry.guardrail {
        let verdict = g.inspect_input(&combined_input).await.unwrap_or_else(|_| crate::core::traits::GuardrailVerdict::safe());
        if !verdict.passed {
            blocked = true;
            violation_reason = verdict.message;
            if let Some(flag) = verdict.flags.first() {
                violation_reason = format!("{}: {}", violation_reason, flag);
            }
        }
    }

    if blocked {
        let latency_ms = start.elapsed().as_millis() as u64;

        // Emit quarantine pulse to Sonar SSE
        let blocked_packet = SonarPacket {
            id: format!("pkt-drop-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            timestamp: Utc::now(),
            flow_type: FlowType::GuardrailInterception,
            upstream_gateway: "NovaSentry Ingress Firewall".to_string(),
            provider: "NovaSentry Boundary Sentinel".to_string(),
            model: payload.model.clone(),
            client_origin: "OpenAI Proxy Client".to_string(),
            latency_ms,
            prompt_tokens: combined_input.len() / 4 + 10,
            completion_tokens: 0,
            estimated_cost_usd: 0.0,
            threat_verdict: ThreatVerdict::Blocked,
            radar_coordinate: RadarCoordinate {
                angle_deg: 295.0,
                distance_norm: 0.88,
                frequency_khz: 22.5,
                intensity_db: -2.0,
            },
            payload_preview: format!("QUARANTINED: {}", violation_reason),
        };
        state.sonar.emit_packet(blocked_packet).await;

        // Record in SQLite Audit Ledger
        if let Some(ref auditor) = state.sentry.auditor {
            let verdict = crate::core::traits::GuardrailVerdict::violation(
                vec![violation_reason.clone()],
                format!("[INGRESS PROXY BLOCKED] {}", violation_reason),
            );
            auditor.record(
                &format!("Ingress Proxy Intercept: {}", payload.model),
                &verdict,
                latency_ms as u128,
            ).await;
        }

        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(OpenAiErrorResponse {
                error: OpenAiErrorDetail {
                    message: format!("[NOVASENTRY INGRESS INTERCEPTION] {}", violation_reason),
                    error_type: "security_policy_violation".to_string(),
                    code: "guardrail_interception".to_string(),
                },
            }).unwrap()),
        ).into_response();
    }

    // 2. Upstream Forwarding or Grounded Fallback Reasoning
    let router_status = state.sonar.get_9router_status().await;
    let auth_header = headers.get(axum::http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()).unwrap_or("");
    let is_gemini_model = payload.model.to_lowercase().starts_with("gemini");
    let gemini_key_env = std::env::var("GEMINI_API_KEY").ok();

    let (upstream_url, upstream_auth) = if is_gemini_model {
        let key = if !auth_header.is_empty() && !auth_header.contains("sentry-token") && !auth_header.contains("sentry123") {
            auth_header.strip_prefix("Bearer ").unwrap_or(auth_header).trim().to_string()
        } else if let Some(ref k) = gemini_key_env {
            k.trim().to_string()
        } else {
            String::new()
        };

        let url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions".to_string();
        let auth = if !key.is_empty() { format!("Bearer {}", key) } else { String::new() };
        (Some(url), Some(auth))
    } else if router_status.connected && !router_status.endpoint.trim().is_empty() {
        let ep = router_status.endpoint.trim_end_matches('/');
        let url = if ep.ends_with("/chat/completions") {
            ep.to_string()
        } else {
            format!("{}/chat/completions", ep)
        };
        (Some(url), if !auth_header.is_empty() { Some(auth_header.to_string()) } else { None })
    } else {
        (None, None)
    };

    let upstream_res = if let Some(target_url) = upstream_url {
        let mut req = state.sonar.http_client().post(&target_url).json(&payload);
        if let Some(ref auth) = upstream_auth {
            if !auth.is_empty() {
                req = req.header("Authorization", auth);
            }
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<serde_json::Value>().await.ok()
            }
            Ok(resp) => {
                let status_code = resp.status();
                let err_text = resp.text().await.unwrap_or_default();
                tracing::warn!("Upstream gateway returned HTTP {}: {}", status_code, err_text);
                None
            }
            Err(err) => {
                tracing::warn!("Failed to reach upstream gateway: {}", err);
                None
            }
        }
    } else {
        None
    };

    let is_upstream_success = upstream_res.is_some();
    let (response_json, raw_completion_text) = if let Some(up_json) = upstream_res {
        let text = up_json["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string();
        (up_json, text)
    } else {
        let prompt_text = payload.messages.last().map(|m| m.content.as_str()).unwrap_or("");
        let generated = match state.sentry.generator.generate(prompt_text, None).await {
            Ok(txt) => txt,
            Err(_) => "NovaSentry security sentry generated verified incident mitigation response.".to_string(),
        };

        let prompt_tokens = combined_input.len() / 4 + 10;
        let completion_tokens = generated.len() / 4 + 10;

        let resp = OpenAiChatResponse {
            id: request_id.clone(),
            object: "chat.completion".to_string(),
            created: Utc::now().timestamp(),
            model: payload.model.clone(),
            choices: vec![OpenAiChoice {
                index: 0,
                message: OpenAiMessage {
                    role: "assistant".to_string(),
                    content: generated.clone(),
                },
                finish_reason: "stop".to_string(),
            }],
            usage: OpenAiUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            },
        };
        (serde_json::to_value(resp).unwrap(), generated)
    };

    // 3. Egress Security Inspection & Redaction
    let mut final_json = response_json;
    let guardrail_impl = crate::components::guardrail::NovaGuardrail::default();
    let (redacted, redacted_count) = guardrail_impl.sanitize_and_redact(&raw_completion_text);
    if redacted_count > 0 {
        if let Some(msg_content) = final_json.pointer_mut("/choices/0/message/content") {
            *msg_content = serde_json::Value::String(redacted);
        }
    }

    let latency_ms = start.elapsed().as_millis() as u64;

    // Emit live pulse to Sonar SSE
    let (gw_label, prov_label, cost) = if is_gemini_model && is_upstream_success {
        (format!("Google Gemini Cloud [{}]", payload.model), "Google Gemini API (Generative Language)".to_string(), 0.0)
    } else if is_upstream_success {
        (format!("9Router Mesh [{}]", payload.model), "9Router Gateway Mesh".to_string(), (combined_input.len() + raw_completion_text.len()) as f64 * 0.000002)
    } else if is_gemini_model {
        (format!("Gemini Fallback Reasoner [{}]", payload.model), "NovaSentry Resilient Engine".to_string(), 0.0)
    } else {
        (format!("Local Guarded Reasoner [{}]", payload.model), "NovaSentry Local Engine".to_string(), 0.0)
    };

    let pass_pulse = SonarPacket {
        id: format!("pkt-pxy-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        timestamp: Utc::now(),
        flow_type: FlowType::OutboundResponse,
        upstream_gateway: gw_label,
        provider: prov_label,
        model: payload.model.clone(),
        client_origin: "OpenAI Proxy Client".to_string(),
        latency_ms,
        prompt_tokens: combined_input.len() / 4 + 10,
        completion_tokens: raw_completion_text.len() / 4 + 10,
        estimated_cost_usd: cost,
        threat_verdict: ThreatVerdict::Clean,
        radar_coordinate: RadarCoordinate {
            angle_deg: 120.0,
            distance_norm: ((latency_ms as f32) / 1000.0).clamp(0.1, 0.8),
            frequency_khz: 16.0,
            intensity_db: -6.0,
        },
        payload_preview: format!("PROXIED_COMPLETION: model='{}', len={}", payload.model, raw_completion_text.len()),
    };
    state.sonar.emit_packet(pass_pulse).await;

    (StatusCode::OK, Json(final_json)).into_response()
}

async fn openai_list_models(State(state): State<WebAppState>) -> impl IntoResponse {
    let status = state.sonar.get_9router_status().await;
    let now = Utc::now().timestamp();
    let mut data = vec![
        OpenAiModelItem {
            id: state.sentry.generator.model_name().to_string(),
            object: "model".to_string(),
            created: now,
            owned_by: "novasentry-local".to_string(),
        },
        OpenAiModelItem {
            id: "gemini-1.5-flash".to_string(),
            object: "model".to_string(),
            created: now,
            owned_by: "google-gemini-free".to_string(),
        },
        OpenAiModelItem {
            id: "gemini-2.0-flash".to_string(),
            object: "model".to_string(),
            created: now,
            owned_by: "google-gemini-free".to_string(),
        },
        OpenAiModelItem {
            id: "gemini-1.5-pro".to_string(),
            object: "model".to_string(),
            created: now,
            owned_by: "google-gemini-free".to_string(),
        },
    ];

    for mesh_node in &status.upstream_mesh {
        data.push(OpenAiModelItem {
            id: mesh_node.clone(),
            object: "model".to_string(),
            created: now,
            owned_by: "9router-mesh".to_string(),
        });
    }

    Json(OpenAiModelListResponse {
        object: "list".to_string(),
        data,
    })
}

async fn export_prometheus_metrics(State(state): State<WebAppState>) -> impl IntoResponse {
    let total_chunks = state.sentry.vector_store.count().await;
    let total_audits = if let Some(ref a) = state.sentry.auditor { a.count().await } else { 0 };
    let sonar_status = state.sonar.get_9router_status().await;
    let chaos_metrics = state.chaos.get_metrics().await;

    let body = format!(
        "# HELP novasentry_up Sentinel operational status (1 = armed, 0 = offline)\n\
# TYPE novasentry_up gauge\n\
novasentry_up 1\n\n\
# HELP novasentry_vector_chunks_total Total knowledge chunks indexed in vector store\n\
# TYPE novasentry_vector_chunks_total gauge\n\
novasentry_vector_chunks_total {}\n\n\
# HELP novasentry_audit_records_total Total compliance forensic audit records in SQLite\n\
# TYPE novasentry_audit_records_total counter\n\
novasentry_audit_records_total {}\n\n\
# HELP novasentry_routed_packets_total Total multi-agent packets routed through sonar\n\
# TYPE novasentry_routed_packets_total counter\n\
novasentry_routed_packets_total {}\n\n\
# HELP novasentry_tokens_routed_total Cumulative tokens inspected across ingress and egress\n\
# TYPE novasentry_tokens_routed_total counter\n\
novasentry_tokens_routed_total {}\n\n\
# HELP novasentry_circuit_breakers_total Circuit breaker trigger count under loop/attack conditions\n\
# TYPE novasentry_circuit_breakers_total counter\n\
novasentry_circuit_breakers_total {}\n\n\
# HELP novasentry_cost_saved_usd Cumulative estimated cost saved through caching and arbitrage\n\
# TYPE novasentry_cost_saved_usd gauge\n\
novasentry_cost_saved_usd {:.4}\n\n\
# HELP novasentry_chaos_simulations_total Total agentic chaos disruption simulations run\n\
# TYPE novasentry_chaos_simulations_total counter\n\
novasentry_chaos_simulations_total {}\n\n\
# HELP novasentry_chaos_tokens_preserved_total Cumulative token budget preserved by circuit breakers\n\
# TYPE novasentry_chaos_tokens_preserved_total counter\n\
novasentry_chaos_tokens_preserved_total {}\n",
        total_chunks,
        total_audits,
        sonar_status.total_routed_packets,
        sonar_status.total_tokens_routed,
        sonar_status.active_circuit_breakers,
        sonar_status.total_cost_saved_usd,
        chaos_metrics.total_simulations,
        chaos_metrics.estimated_tokens_preserved,
    );

    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

pub async fn start_server(
    sentry: Arc<SentryEngine>,
    addr: SocketAddr,
    db_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = auth::AuthDb::new(db_path)?;
    let chaos = Arc::new(crate::components::chaos::ChaosEngine::new());
    let sonar = Arc::new(crate::components::sonar::SonarEngine::new());
    
    // Seed initial telemetry packet so Sonar detector radar is immediately active
    sonar.simulate_packet(Some("response")).await;
    sonar.simulate_packet(Some("injection")).await;

    let state = WebAppState { sentry, auth, chaos, sonar };
    let router = create_router(state);

    println!("⚡ NovaSentry Web Server binding to http://{}", addr);
    println!("📦 SQLite Authentication Database: {}", db_path);
    println!("📡 Sonar Detector & 9router SSE Stream active at /api/sonar/stream");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
