# 🛡️ NovaSentry: Autonomous Multi-Agent AI RAG Security Sentry

[![Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Framework](https://img.shields.io/badge/Web_Server-Axum_0.7-blue.svg)](https://github.com/tokio-rs/axum)
[![UI/UX](https://img.shields.io/badge/Frontend-Tailwind_CSS_SOC_Dashboard-38bdf8.svg?logo=tailwindcss)](https://tailwindcss.com/)
[![Runtime](https://img.shields.io/badge/Async_Runtime-Tokio_1.38-red.svg)](https://tokio.rs/)
[![License](https://img.shields.io/badge/License-MIT_OR_Apache--2.0-green.svg)](LICENSE)

**NovaSentry** is a high-performance, modular AI RAG (Retrieval-Augmented Generation) security sentry and knowledge intelligence engine written in Rust. It autonomously monitors live security telemetry, intercepts adversarial prompt injections, and generates incident triage analysis grounded in verified organizational knowledge and playbooks.

Featuring an embedded **Tailwind CSS Cyberpunk / SOC Sentinel WebUI**, NovaSentry provides real-time telemetry inspection, hybrid vector search ranking, attack simulation, and live compliance audit logs with zero external Node/npm dependencies.

---

## 🏛️ System Architecture

```text
       ┌────────────────────────────────────────────────────────┐
       │      Incoming Live Telemetry / User Prompt Alert       │
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │       NovaGuardrail (Input Scanner)       │
             │   - Prompt Injection Detection            │
             │   - Adversarial Instruction Tampering     │
             └─────────────────────┬─────────────────────┘
                       Passed      │     Blocked ──► [Immediate Sentry Alert & Triage]
                                   ▼
             ┌───────────────────────────────────────────┐
             │              HybridRetriever              │
             │   - Dense Cosine Similarity (Embedder)    │
             │   - Sparse Lexical Match & RRF Fusion     │
             └─────────────────────┬─────────────────────┘
                                   │ Top-K Chunks
                                   ▼
             ┌───────────────────────────────────────────┐
             │              PromptBuilder                │
             │   - Formatted Citations & Grounding Rules │
             └─────────────────────┬─────────────────────┘
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │         LlmClient (Synthesizer Engine)    │
             │   - Context-grounded Incident Analysis    │
             └─────────────────────┬─────────────────────┘
                                   │ Raw Synthesis
                                   ▼
             ┌───────────────────────────────────────────┐
             │       NovaGuardrail (Output Scanner)      │
             │   - Credential / Secret Leak Prevention   │
             │   - Confidentiality Policy Enforcement    │
             └─────────────────────┬─────────────────────┘
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │         SentryAuditor & AnalysisReport    │
             │   - Governance Logging & Remediation Plan │
             └───────────────────────────────────────────┘
```

---

## ✨ Key Features

1. **⚡ Cyberpunk & Professional SOC Sentinel WebUI**:
   - Modern Tailwind CSS dark glassmorphism dashboard styled for Security Operations Centers (SOC).
   - Embedded directly in the Rust binary via `include_str!` — runs instantly without requiring Node.js, npm, or webpack.
   - Live execution pipeline visualizer tracking each stage from input scanner to audit record.

2. **🛡️ Dual-Perimeter Guardrail Defense (`NovaGuardrail`)**:
   - **Ingress Scanner**: Intercepts jailbreaks, prompt injections, and adversarial instruction tampering (e.g. `ignore previous instructions`, `bypass policy`, `dan mode`).
   - **Egress Scanner**: Prevents confidential credential exfiltration, JWT leaks, and AWS access key disclosure.

3. **🔍 Hybrid RAG Knowledge Retrieval (`HybridRetriever`)**:
   - Combines 384-dimensional dense semantic vector similarity with sparse lexical matching using **Reciprocal Rank Fusion (RRF)**.
   - Grounded context synthesis ensures that mitigation steps match official incident response runbooks and CVE advisories.

4. **📚 Dynamic Runbook Ingestion**:
   - Partitions playbooks with `RecursiveCharacterChunker` (token windowing with configurable boundary overlap).
   - Indexes embeddings into `InMemoryVectorStore` with concurrent thread-safe read/write operations.

5. **📋 Governance & Compliance Audit Trail (`SentryAuditor`)**:
   - In-memory immutable audit log recording latency (in milliseconds), risk scores, verdict flags, and full incident telemetry history.

---

## 🧩 Modular Trait Contracts

NovaSentry isolates responsibilities via strict async traits defined in `src/core/traits.rs`:

| Trait | Core Responsibilities | Default Implementation |
|---|---|---|
| `Chunker` | Document partitioning & semantic windowing | `RecursiveCharacterChunker` |
| `Embedder` | Text to dense vector transformations | `MockEmbedder` (384-dim normalized pseudo-semantic space) |
| `VectorStore` | Chunk indexing & vector similarity search | `InMemoryVectorStore` |
| `Retriever` | Hybrid multi-stage knowledge retrieval | `HybridRetriever` (Dense + Sparse RRF) |
| `LlmClient` | Grounded context synthesis and reasoning | `MockLlmGenerator` (`NovaSentry-Reasoner-v1`) |
| `GuardrailValidator` | Input injection scanning & output secret filtering | `NovaGuardrail` |
| `SentryAuditor` | Compliance audit trail telemetry logging | `SentryAuditor` |

---

## 🚀 Quickstart

### 1. Launch Web Dashboard (Default)

Launch the production sentinel service and open the WebUI in your browser:

```bash
cargo run
```

Then navigate to: **`http://localhost:3000`** (or `http://127.0.0.1:3000`).

Custom port option:

```bash
cargo run -- --port 8080
```

### 2. Run Terminal CLI Demo

Run the automated headless architecture demo showcasing legitimate alert triage vs adversarial prompt injection:

```bash
cargo run -- --demo
```

### 3. Run Test Suite

Run all unit and integration tests:

```bash
cargo test
```

---

## 🔌 REST API Reference

NovaSentry provides a REST API via Axum on port `3000`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the embedded Tailwind CSS SOC Web Dashboard |
| `GET` | `/api/stats` | Retrieves current sentry status, chunk count, audit count, and model metadata |
| `GET` | `/api/knowledge` | Lists all indexed vector documents and passage chunks |
| `POST` | `/api/knowledge` | Ingests and vectorizes a new security playbook / CVE document |
| `POST` | `/api/investigate` | Submits telemetry for guardrail scanning, hybrid retrieval, and LLM triage |
| `GET` | `/api/audit` | Retrieves all recorded compliance and sentry audit records |
| `POST` | `/api/guardrail/test` | Standalone evaluator for input injection and output data leakage rules |

### Example: Investigating an Alert via cURL

```bash
curl -X POST http://127.0.0.1:3000/api/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "title": "ALERT-9042: Detected privilege escalation on auth-pod-worker-02",
    "severity": "Critical",
    "source": "k8s-audit-sensor-us-east-1",
    "raw_telemetry": "Process /bin/nsenter spawned with hostPID=true attempting memory dump of /etc/kubernetes/pki"
  }'
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) or Apache-2.0.
