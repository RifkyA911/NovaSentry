use async_trait::async_trait;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use crate::core::error::SentryError;
use crate::core::models::VectorMath;
use crate::core::traits::Embedder;

/// A deterministic, pseudo-semantic embedder generating 384-dimensional normalized vectors.
/// Uses character n-grams and token hashing to map semantic overlap into cosine space.
#[derive(Debug, Clone)]
pub struct MockEmbedder {
    dimension: usize,
}

impl Default for MockEmbedder {
    fn default() -> Self {
        Self { dimension: 384 }
    }
}

impl MockEmbedder {
    pub fn new(dimension: usize) -> Self {
        Self { dimension }
    }

    /// Hash a token to a bucket index and weight.
    fn hash_token(&self, token: &str) -> (usize, f32) {
        let mut hasher = DefaultHasher::new();
        token.to_lowercase().hash(&mut hasher);
        let hash = hasher.finish();

        let index = (hash as usize) % self.dimension;
        let sign = if (hash >> 32) % 2 == 0 { 1.0f32 } else { -1.0f32 };
        let weight = 1.0 + ((hash % 100) as f32 / 100.0);

        (index, sign * weight)
    }
}

#[async_trait]
impl Embedder for MockEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, SentryError> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(vec![0.0; self.dimension]);
        }

        let mut vector = vec![0.0f32; self.dimension];

        // 1. Unigram token distribution
        for word in trimmed.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-') {
            if word.is_empty() {
                continue;
            }
            let (idx, val) = self.hash_token(word);
            vector[idx] += val;

            // Character trigram subwords for lexical / morphological similarity
            if word.len() >= 3 {
                for window in word.as_bytes().windows(3) {
                    if let Ok(sub) = std::str::from_utf8(window) {
                        let (sub_idx, sub_val) = self.hash_token(sub);
                        vector[sub_idx] += sub_val * 0.35;
                    }
                }
            }
        }

        // 2. Normalize to unit hypersphere
        let normalized = VectorMath::normalize(&vector);
        Ok(normalized)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}
