# NovaSentry: Autonomous Multi-Agent AI RAG Security Sentry

NovaSentry is a high-performance, modular AI RAG (Retrieval-Augmented Generation) security sentry and knowledge intelligence engine written in Rust. It autonomously monitors live security telemetry, intercepts adversarial prompt injections, and generates incident triage analysis grounded in verified organizational knowledge.

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

## 🧩 Modular Trait Contracts (Swarm Member Integration)

NovaSentry isolates responsibilities via strict async traits defined in `src/core/traits.rs`:

| Trait | Core Responsibilities | Implementations |
|---|---|---|
| `Chunker` | Document partitioning & semantic windowing | `RecursiveCharacterChunker` |
| `Embedder` | Text to dense vector transformations | `MockEmbedder` (384-dim pseudo-semantic hashing) |
| `VectorStore` | Chunk indexing & vector similarity search | `InMemoryVectorStore` |
| `Retriever` | Hybrid multi-stage knowledge retrieval | `HybridRetriever` (Dense + Sparse RRF) |
| `LlmClient` | Grounded context synthesis and reasoning | `MockLlmGenerator` |
| `GuardrailValidator` | Input injection scanning & output secret filtering | `NovaGuardrail` |

## 🚀 Quickstart & Demo

Run the end-to-end prototype demo:

```bash
cargo run
```

Run test suite:

```bash
cargo test
```
