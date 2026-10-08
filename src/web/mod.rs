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
