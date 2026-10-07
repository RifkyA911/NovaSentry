use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::core::traits::GuardrailVerdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub passed: bool,
    pub risk_score: f32,
    pub flags: Vec<String>,
    pub latency_ms: u128,
}

/// In-memory thread-safe security audit trail for compliance, incident replay, and forensic analysis.
#[derive(Clone, Default)]
pub struct SentryAuditor {
    records: Arc<RwLock<Vec<AuditRecord>>>,
}

impl SentryAuditor {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn record(&self, action: &str, verdict: &GuardrailVerdict, latency_ms: u128) {
        let entry = AuditRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action: action.to_string(),
            passed: verdict.passed,
            risk_score: verdict.risk_score,
            flags: verdict.flags.clone(),
            latency_ms,
        };

        let mut lock = self.records.write().await;
        lock.push(entry);
    }

    pub async fn get_records(&self) -> Vec<AuditRecord> {
        let lock = self.records.read().await;
        lock.clone()
    }

    pub async fn count(&self) -> usize {
        let lock = self.records.read().await;
        lock.len()
    }
}
