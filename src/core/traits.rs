use async_trait::async_trait;
use crate::core::error::SentryError;
use crate::core::models::{Chunk, Document, SearchResult, VectorDocument};

/// Component contract for splitting documents into chunks.
pub trait Chunker: Send + Sync {
    fn chunk(&self, document: &Document) -> Result<Vec<Chunk>, SentryError>;
}

/// Component contract for generating vector embeddings from text.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// Generate embedding vector for a single text string.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, SentryError>;

    /// Batch generate embeddings for multiple strings.
    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, SentryError> {
        let mut results = Vec::with_capacity(texts.len());
        for text in texts {
            results.push(self.embed(text).await?);
        }
        Ok(results)
    }

    /// Embedding dimension size (e.g. 384, 768, 1536).
    fn dimension(&self) -> usize;
}

/// Component contract for storing and querying vector embeddings.
#[async_trait]
pub trait VectorStore: Send + Sync {
    /// Insert a single vector document into the store.
    async fn insert(&self, doc: VectorDocument) -> Result<(), SentryError>;

    /// Insert a batch of vector documents.
    async fn insert_batch(&self, docs: Vec<VectorDocument>) -> Result<(), SentryError> {
        for doc in docs {
            self.insert(doc).await?;
        }
        Ok(())
    }

    /// Retrieve the top-k most similar chunks for a given query vector.
    async fn similarity_search(&self, query_vec: &[f32], limit: usize) -> Result<Vec<SearchResult>, SentryError>;

    /// Return the total count of documents in the store.
    async fn count(&self) -> usize;

    /// Clear all documents in the store.
    async fn clear(&self) -> Result<(), SentryError>;

    /// Return all stored vector documents (useful for inspection and WebUI).
    async fn get_all_documents(&self) -> Result<Vec<VectorDocument>, SentryError> {
        Ok(Vec::new())
    }
}

/// Component contract for modern RAG retrieval (Dense, Sparse, or Hybrid).
#[async_trait]
pub trait Retriever: Send + Sync {
    /// Retrieve relevant knowledge chunks given a textual query.
    async fn retrieve(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>, SentryError>;
}

/// Component contract for LLM generation and reasoning.
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// Generate a completion given a prompt and optional system context.
    async fn generate(&self, prompt: &str, system_context: Option<&str>) -> Result<String, SentryError>;

    /// Model name or identifier.
    fn model_name(&self) -> &str {
        "NovaSentry-Reasoner-v1"
    }
}

/// Security assessment verdict from NovaSentry guardrail scan.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GuardrailVerdict {
    pub passed: bool,
    pub risk_score: f32,
    pub flags: Vec<String>,
    pub message: String,
}

impl GuardrailVerdict {
    pub fn safe() -> Self {
        Self {
            passed: true,
            risk_score: 0.0,
            flags: Vec::new(),
            message: "Scan passed all security criteria.".to_string(),
        }
    }

    pub fn violation(flags: Vec<String>, message: impl Into<String>) -> Self {
        Self {
            passed: false,
            risk_score: 1.0,
            flags,
            message: message.into(),
        }
    }
}

/// Component contract for prompt injection, adversarial defense, and secret leakage guardrails.
#[async_trait]
pub trait GuardrailValidator: Send + Sync {
    /// Inspect input prompt or telemetry payload for adversarial attacks.
    async fn inspect_input(&self, input: &str) -> Result<GuardrailVerdict, SentryError>;

    /// Inspect output synthesis for secret leakage or policy breaches.
    async fn inspect_output(&self, output: &str, context: &str) -> Result<GuardrailVerdict, SentryError>;
}
