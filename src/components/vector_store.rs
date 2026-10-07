use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::core::error::SentryError;
use crate::core::models::{SearchResult, VectorDocument, VectorMath};
use crate::core::traits::VectorStore;

/// In-memory vector database with concurrent read/write access and cosine similarity ranking.
#[derive(Debug, Clone)]
pub struct InMemoryVectorStore {
    documents: Arc<RwLock<Vec<VectorDocument>>>,
}

impl Default for InMemoryVectorStore {
    fn default() -> Self {
        Self {
            documents: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl InMemoryVectorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl VectorStore for InMemoryVectorStore {
    async fn insert(&self, doc: VectorDocument) -> Result<(), SentryError> {
        let mut docs = self.documents.write().await;
        docs.push(doc);
        Ok(())
    }

    async fn insert_batch(&self, docs: Vec<VectorDocument>) -> Result<(), SentryError> {
        let mut lock = self.documents.write().await;
        lock.extend(docs);
        Ok(())
    }

    async fn similarity_search(
        &self,
        query_vec: &[f32],
        limit: usize,
    ) -> Result<Vec<SearchResult>, SentryError> {
        if query_vec.is_empty() {
            return Err(SentryError::VectorStoreError(
                "Query vector cannot be empty".to_string(),
            ));
        }

        let docs = self.documents.read().await;
        if docs.is_empty() {
            return Ok(Vec::new());
        }

        let mut scored: Vec<(f32, &VectorDocument)> = docs
            .iter()
            .map(|doc| {
                let score = VectorMath::cosine_similarity(query_vec, &doc.vector);
                (score, doc)
            })
            .collect();

        // Sort descending by score
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let results = scored
            .into_iter()
            .take(limit)
            .enumerate()
            .map(|(rank, (score, doc))| SearchResult {
                chunk: doc.chunk.clone(),
                score,
                rank: rank + 1,
            })
            .collect();

        Ok(results)
    }

    async fn count(&self) -> usize {
        let docs = self.documents.read().await;
        docs.len()
    }

    async fn clear(&self) -> Result<(), SentryError> {
        let mut docs = self.documents.write().await;
        docs.clear();
        Ok(())
    }
}
