use thiserror::Error;

/// Core error types for the NovaSentry engine and its components.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SentryError {
    #[error("Document ingestion error: {0}")]
    IngestionError(String),

    #[error("Chunking error: {0}")]
    ChunkingError(String),

    #[error("Embedding calculation error: {0}")]
    EmbeddingError(String),

    #[error("Vector store error: {0}")]
    VectorStoreError(String),

    #[error("Retrieval error: {0}")]
    RetrievalError(String),

    #[error("LLM Generation error: {0}")]
    GenerationError(String),

    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("Configuration or parameter error: {0}")]
    ConfigError(String),

    #[error("Guardrail security violation: {0}")]
    GuardrailViolation(String),
}
