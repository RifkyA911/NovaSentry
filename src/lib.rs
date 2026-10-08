//! # NovaSentry
//!
//! Autonomous Security Sentinel & Knowledge-Augmented RAG Engine written in Rust.

pub mod components;
pub mod core;
pub mod web;

pub mod prelude {
    pub use crate::components::{
        ChaosEngine, HybridRetriever, InMemoryVectorStore, MockEmbedder, MockLlmGenerator,
        NovaGuardrail, PromptBuilder, RecursiveCharacterChunker, SentryAuditor, SentryEngine,
        SonarEngine, TunnelProbeResult,
    };
    pub use crate::core::{
        AlertSeverity, AnalysisReport, Chunk, Chunker, Document, Embedder, GuardrailValidator,
        GuardrailVerdict, LlmClient, Retriever, SearchResult, SentryAlert, SentryError,
        VectorDocument, VectorMath, VectorStore,
    };
}
