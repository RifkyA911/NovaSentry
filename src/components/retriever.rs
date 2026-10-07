use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use crate::core::error::SentryError;
use crate::core::models::SearchResult;
use crate::core::traits::{Embedder, Retriever, VectorStore};

/// Hybrid Retriever combining Dense Vector Similarity Search with Sparse Term Matching via Reciprocal Rank Fusion (RRF).
pub struct HybridRetriever {
    embedder: Arc<dyn Embedder>,
    vector_store: Arc<dyn VectorStore>,
    rrf_k: f32,
}

impl HybridRetriever {
    pub fn new(embedder: Arc<dyn Embedder>, vector_store: Arc<dyn VectorStore>) -> Self {
        Self {
            embedder,
            vector_store,
            rrf_k: 60.0,
        }
    }

    pub fn with_rrf_k(mut self, k: f32) -> Self {
        self.rrf_k = k;
        self
    }

    /// Compute simple lexical / keyword match score for sparse ranking.
    fn compute_lexical_score(query_tokens: &[String], content: &str) -> f32 {
        let content_lower = content.to_lowercase();
        let mut matches = 0.0f32;

        for token in query_tokens {
            if content_lower.contains(token) {
                matches += 1.0;
            }
        }

        matches
    }
}

#[async_trait]
impl Retriever for HybridRetriever {
    async fn retrieve(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>, SentryError> {
        let trimmed_query = query.trim();
        if trimmed_query.is_empty() {
            return Ok(Vec::new());
        }

        // 1. Dense retrieval pass
        let query_vec = self.embedder.embed(trimmed_query).await?;
        let dense_results = self.vector_store.similarity_search(&query_vec, limit * 2).await?;

        // 2. Sparse lexical tokenization
        let query_tokens: Vec<String> = trimmed_query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() > 2)
            .map(|w| w.to_lowercase())
            .collect();

        // 3. Reciprocal Rank Fusion (RRF)
        let mut rrf_scores: HashMap<String, (f32, SearchResult)> = HashMap::new();

        // Rank contribution from dense search
        for (dense_rank, result) in dense_results.into_iter().enumerate() {
            let score_dense = 1.0 / (self.rrf_k + (dense_rank as f32) + 1.0);
            let chunk_id = result.chunk.id.clone();

            let lexical_score = Self::compute_lexical_score(&query_tokens, &result.chunk.content);
            let combined = score_dense + (lexical_score * 0.05);

            rrf_scores.insert(chunk_id, (combined, result));
        }

        // Sort by final fused RRF score
        let mut fused_list: Vec<(f32, SearchResult)> = rrf_scores.into_values().collect();
        fused_list.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let top_results = fused_list
            .into_iter()
            .take(limit)
            .enumerate()
            .map(|(rank, (fused_score, mut item))| {
                item.score = fused_score;
                item.rank = rank + 1;
                item
            })
            .collect();

        Ok(top_results)
    }
}
