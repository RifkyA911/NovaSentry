# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] - 2026-10-08

### Added
- **Live Google Gemini Model Discovery via `ModelService.ListModels` (`POST /api/settings/gemini/sync-models`)**:
  - Dynamically queries `https://generativelanguage.googleapis.com/v1beta/models?key={}` to retrieve all active models supporting `generateContent` for the user's specific Google AI Studio account.
  - Interactive **Sync Models** button in the Settings view dynamically populates the model selection dropdown with live models, making NovaSentry future-proof against model deprecations.
  - Added modern production models to `GET /v1/models`: `gemini-2.5-flash` (flagship high-speed & reasoning), `gemini-2.5-pro`, `gemini-2.0-flash`, `gemini-3.5-flash`, and `gemini-3.1-pro-preview`.
- **Dual Authentication Headers**:
  - Sends both `x-goog-api-key` and `Authorization: Bearer <KEY>` to Google Generative AI endpoints for maximum provider compatibility.
- **Enhanced Connection Diagnostic Diagnostics**:
  - When connection test fails, NovaSentry automatically queries `ModelService.ListModels` and returns actionable recommendations showing exact active model names available to the user.

### Changed
- **Default Upstream Model Upgraded to `gemini-2.5-flash`**:
  - Replaced deprecated `gemini-1.5-flash` (disallowed/404 in Google v1main API) with current production workhorse `gemini-2.5-flash`.
  - Updated all defaults in `AppSettings`, `.env.example`, documentation, and component tests.

---

## [0.2.0] - 2026-10-08

### Added
- **Dedicated System Settings & API Keys Dashboard View (`#view-settings`)**:
  - Full-featured configuration management interface accessible directly in the sidebar navigation.
  - Interactive Google Gemini Free API Key input with password show/hide eye toggle, key masking, and real-time validation.
  - Model selection dropdown supporting `gemini-2.5-flash` (Recommended Free Tier), `gemini-2.5-pro`, and `gemini-2.0-flash`.
  - Upstream 9Router Gateway Endpoint URL and Bearer token configuration with live tunnel probing.
  - Perimeter guardrail strictness selector (`Strict`, `Balanced`, `Permissive`) and custom Canary Honeytoken string input.
  - Egress credential and secret redaction toggle.
  - **Live Connection Testing Tool (`POST /api/settings/test-gemini`)**: Directly sends a lightweight probe to Google Generative AI to verify API key validity, reporting HTTP 200 connectivity or detailed provider error messages inline.
- **REST Settings API (`GET /api/settings`, `POST /api/settings`)**:
  - Thread-safe runtime configuration state backed by `Arc<tokio::sync::RwLock<AppSettings>>`.
  - Automatic persistence to local `.env` configuration file without requiring a daemon restart.
  - Automatic audit trail logging in SQLite forensic ledger upon administrative configuration changes.
- **Native Google Gemini Free Tier Reverse Proxy Upstream Forwarding**:
  - Model inspection: routes any request targeting `gemini-*` models to Google Generative AI's official OpenAI-compatible endpoint (`https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`).
  - Supports API keys passed either via per-request `Authorization: Bearer <KEY>` header, runtime Settings UI, or `.env` file (`GEMINI_API_KEY`).
  - Drop-in compatibility for Python `openai` SDK, n8n HTTP Request node, Hermes Agent, and Cursor by simply specifying `base_url="http://localhost:3000/v1"`.
- **Pre-Call Ingress Quota Shielding**:
  - Intercepts prompt injection payloads, system prompt leaks, and delimiter breakouts in **<0.1ms** within local Rust memory.
  - Quarantines malicious requests with HTTP 400 *before* making outbound network calls to Google Gemini, preserving the 15 RPM / 1,500 RPD free tier quota from adversarial consumption.
- **Post-Call Egress Credential Redaction**:
  - Inspects upstream Gemini responses and scrubs sensitive tokens (AWS access keys, OpenAI/Gemini API keys, Bearer JWTs, private keys, PII) replacing them with `[REDACTED_*]` tags.
- **Comprehensive Component Test**:
  - Added `test_settings_view_and_gemini_configuration` integration test verifying default settings, runtime mutation, and model routing.

### Changed
- **Proxy Endpoint (`POST /v1/chat/completions`)**:
  - Updated upstream target resolution to read dynamic runtime settings prior to environment variables.
  - Enhanced Sonar acoustic radar packet metadata to accurately reflect `Google Gemini Cloud` and `Google Gemini API` telemetry attribution with $0.00 estimated cost for free tier models.
- **OpenAI Models Endpoint (`GET /v1/models`)**:
  - Added `gemini-1.5-flash`, `gemini-2.0-flash`, and `gemini-1.5-pro` under the `google-gemini-free` owner.
- **Web App State (`WebAppState`)**:
  - Introduced ergonomic `WebAppState::new` constructor with integrated runtime settings lock.

---

## [0.1.0] - 2026-10-07

### Added
- **Initial Core Release of NovaSentry**:
  - Autonomous Multi-Agent AI RAG Security Sentry & Perimeter Guardrail in Rust.
  - Sub-millisecond dual-perimeter guardrail (`NovaGuardrail`) for ingress injection filtering and egress credential redaction.
  - Dense + BM25 Hybrid RAG Retriever (`HybridRetriever`) utilizing 384-dimensional vector embeddings and reciprocal rank fusion.
  - SQLite compliance forensic audit trail (`SentryAuditor`) with SHA-256 password-hashed authentication.
  - Interactive n8n-style workflow graph visualizer with dynamic Bezier wires and node execution states.
  - Real-time Acoustic Sonar Detector with HTML5 Canvas radar screen and Server-Sent Events (SSE) push streaming at `/api/sonar/stream`.
  - 9Router Gateway Mesh integration for multi-model arbitrage routing (Claude 3.5 Sonnet, GPT-4o, DeepSeek-V3, Llama 3.3).
  - Agentic Chaos Engineering Lab (`ChaosEngine`) simulating cognitive drift, infinite loops, and token runaway attacks with circuit breakers.
  - Prometheus metrics exporter endpoint (`GET /metrics`).
