use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use crate::components::sentry::SentryEngine;
use crate::core::models::{AlertSeverity, Document, SentryAlert};

pub mod auth;

pub const INDEX_HTML: &str = include_str!("assets/index.html");
pub const LOGO_SVG: &str = include_str!("assets/logo.svg");

#[derive(Clone)]
pub struct WebAppState {
    pub sentry: Arc<SentryEngine>,
    pub auth: auth::AuthDb,
    pub chaos: Arc<crate::components::chaos::ChaosEngine>,
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

pub fn create_router(state: WebAppState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/assets/logo.svg", get(serve_logo))
        .route("/api/stats", get(get_stats))
        .route("/api/knowledge", get(get_knowledge).post(ingest_knowledge))
        .route("/api/investigate", post(investigate_alert))
        .route("/api/audit", get(get_audit_trail))
        .route("/api/guardrail/test", post(test_guardrail))
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

    let start = Instant::now();
    match state.sentry.investigate_alert(&alert).await {
        Ok(report) => {
            let latency_ms = start.elapsed().as_millis();
            let guardrail_interception = report.title.contains("[SECURITY VIOLATION DETECTED]");
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
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(result).unwrap_or_default())).into_response(),
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
    let state = WebAppState { sentry, auth, chaos };
    let router = create_router(state);

    println!("⚡ NovaSentry Web Server binding to http://{}", addr);
    println!("📦 SQLite Authentication Database: {}", db_path);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
