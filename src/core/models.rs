use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity classification for security sentry alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Raw source document ingested into NovaSentry (runbooks, architecture notes, CVEs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Document {
    pub id: String,
    pub title: String,
    pub content: String,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

impl Document {
    pub fn new(title: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            title: title.into(),
            content: content.into(),
            metadata: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A smaller semantic passage derived from a parent Document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Chunk {
    pub id: String,
    pub document_id: String,
    pub chunk_index: usize,
    pub content: String,
    pub metadata: HashMap<String, String>,
    pub token_count_approx: usize,
}

impl Chunk {
    pub fn new(document_id: impl Into<String>, chunk_index: usize, content: impl Into<String>) -> Self {
        let text = content.into();
        let tokens = text.split_whitespace().count();
        Self {
            id: Uuid::new_v4().to_string(),
            document_id: document_id.into(),
            chunk_index,
            content: text,
            metadata: HashMap::new(),
            token_count_approx: tokens,
        }
    }
}

/// A chunk packaged with its vector representation for indexing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VectorDocument {
    pub chunk: Chunk,
    pub vector: Vec<f32>,
}

impl VectorDocument {
    pub fn new(chunk: Chunk, vector: Vec<f32>) -> Self {
        Self { chunk, vector }
    }
}

/// A retrieved chunk matching a query, with relevance score and rank.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchResult {
    pub chunk: Chunk,
    pub score: f32,
    pub rank: usize,
}

/// An incoming security telemetry alert needing automated RAG investigation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SentryAlert {
    pub id: String,
    pub title: String,
    pub severity: AlertSeverity,
    pub source: String,
    pub raw_telemetry: String,
    pub timestamp: DateTime<Utc>,
}

impl SentryAlert {
    pub fn new(
        title: impl Into<String>,
        severity: AlertSeverity,
        source: impl Into<String>,
        raw_telemetry: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            title: title.into(),
            severity,
            source: source.into(),
            raw_telemetry: raw_telemetry.into(),
            timestamp: Utc::now(),
        }
    }
}

/// Autonomous incident triage report synthesized by Sentry with RAG context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisReport {
    pub incident_id: String,
    pub title: String,
    pub assessed_risk: AlertSeverity,
    pub root_cause_analysis: String,
    pub relevant_knowledge: Vec<SearchResult>,
    pub remediation_steps: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

/// Utility math operations for dense embedding vectors.
pub struct VectorMath;

impl VectorMath {
    /// Compute cosine similarity between two float vectors.
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() || a.is_empty() {
            return 0.0;
        }

        let mut dot = 0.0f32;
        let mut norm_a = 0.0f32;
        let mut norm_b = 0.0f32;

        for (x, y) in a.iter().zip(b.iter()) {
            dot += x * y;
            norm_a += x * x;
            norm_b += y * y;
        }

        let denom = norm_a.sqrt() * norm_b.sqrt();
        if denom > 0.0 {
            dot / denom
        } else {
            0.0
        }
    }

    /// Normalize vector in-place or return normalized vector.
    pub fn normalize(vec: &[f32]) -> Vec<f32> {
        let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 0.0 {
            vec.iter().map(|v| v / norm).collect()
        } else {
            vec.to_vec()
        }
    }
}
