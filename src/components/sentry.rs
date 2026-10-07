use std::sync::Arc;
use std::time::Instant;
use chrono::Utc;
use crate::components::auditor::SentryAuditor;
use crate::components::generator::PromptBuilder;
use crate::core::error::SentryError;
use crate::core::models::{AlertSeverity, AnalysisReport, Document, SentryAlert, VectorDocument};
use crate::core::traits::{Chunker, Embedder, GuardrailValidator, GuardrailVerdict, LlmClient, Retriever, VectorStore};

/// Autonomous Sentry Engine coordinating ingestion, RAG vector retrieval, and LLM triage synthesis.
pub struct SentryEngine {
    pub chunker: Arc<dyn Chunker>,
    pub embedder: Arc<dyn Embedder>,
    pub vector_store: Arc<dyn VectorStore>,
    pub retriever: Arc<dyn Retriever>,
    pub generator: Arc<dyn LlmClient>,
    pub guardrail: Option<Arc<dyn GuardrailValidator>>,
    pub auditor: Option<SentryAuditor>,
}

impl SentryEngine {
    pub fn new(
        chunker: Arc<dyn Chunker>,
        embedder: Arc<dyn Embedder>,
        vector_store: Arc<dyn VectorStore>,
        retriever: Arc<dyn Retriever>,
        generator: Arc<dyn LlmClient>,
    ) -> Self {
        Self {
            chunker,
            embedder,
            vector_store,
            retriever,
            generator,
            guardrail: None,
            auditor: None,
        }
    }

    pub fn with_guardrail(mut self, guardrail: Arc<dyn GuardrailValidator>) -> Self {
        self.guardrail = Some(guardrail);
        self
    }

    pub fn with_auditor(mut self, auditor: SentryAuditor) -> Self {
        self.auditor = Some(auditor);
        self
    }

    /// Ingest and index a knowledge base document into the vector store.
    pub async fn ingest_knowledge(&self, doc: Document) -> Result<usize, SentryError> {
        let chunks = self.chunker.chunk(&doc)?;
        if chunks.is_empty() {
            return Ok(0);
        }

        let texts: Vec<String> = chunks.iter().map(|c| c.content.clone()).collect();
        let vectors = self.embedder.embed_batch(&texts).await?;

        let vector_docs: Vec<VectorDocument> = chunks
            .into_iter()
            .zip(vectors.into_iter())
            .map(|(chunk, vector)| VectorDocument::new(chunk, vector))
            .collect();

        let count = vector_docs.len();
        self.vector_store.insert_batch(vector_docs).await?;

        Ok(count)
    }

    /// Triage an incoming alert by retrieving relevant incident runbooks and generating remediation steps.
    pub async fn investigate_alert(&self, alert: &SentryAlert) -> Result<AnalysisReport, SentryError> {
        let start = Instant::now();
        let query = format!("{} {}", alert.title, alert.raw_telemetry);

        // 1. Guardrail input inspection (checks for adversarial telemetry or injection attempts)
        let verdict = if let Some(guardrail) = &self.guardrail {
            let input_verdict = guardrail.inspect_input(&query).await?;
            if !input_verdict.passed {
                let latency = start.elapsed().as_millis();
                if let Some(auditor) = &self.auditor {
                    auditor.record(&alert.title, &input_verdict, latency).await;
                }
                return Ok(AnalysisReport {
                    incident_id: alert.id.clone(),
                    title: format!("[SECURITY VIOLATION DETECTED] {}", alert.title),
                    assessed_risk: AlertSeverity::Critical,
                    root_cause_analysis: format!(
                        "CRITICAL ALERT: Malicious prompt injection or adversarial tampering detected in incoming telemetry!\nFlags: {:?}",
                        input_verdict.flags
                    ),
                    relevant_knowledge: Vec::new(),
                    remediation_steps: vec![
                        "IMMEDIATE ACTION: Block traffic from ingress source.".to_string(),
                        "Quarantine origin node/sensor and invalidate bearer tokens.".to_string(),
                        "Trigger Level-1 Emergency Incident Response.".to_string(),
                    ],
                    generated_at: Utc::now(),
                });
            }
            input_verdict
        } else {
            GuardrailVerdict::safe()
        };

        let relevant_knowledge = self.retriever.retrieve(&query, 3).await?;

        let prompt = PromptBuilder::build_rag_prompt(&query, &relevant_knowledge);
        let raw_analysis_text = self
            .generator
            .generate(&prompt, Some("NovaSentry Sentinel Policy: Enforce Zero Trust & Fast Containment"))
            .await?;

        // 2. Guardrail output inspection (checks for secret / key leaks in synthesized text)
        let (analysis_text, final_verdict) = if let Some(guardrail) = &self.guardrail {
            let out_verdict = guardrail.inspect_output(&raw_analysis_text, &query).await?;
            if !out_verdict.passed {
                (
                    format!("CONFIDENTIALITY POLICY ENFORCED: Output redacted. Reason: {}", out_verdict.message),
                    out_verdict
                )
            } else {
                (raw_analysis_text, verdict)
            }
        } else {
            (raw_analysis_text, verdict)
        };

        // Extract bullet remediation steps if present
        let remediation_steps: Vec<String> = analysis_text
            .lines()
            .filter(|line| line.contains("ACTION:") || line.trim_start().starts_with("• ACTION"))
            .map(|line| line.trim().to_string())
            .collect();

        let final_steps = if remediation_steps.is_empty() {
            vec![
                "Quarantine affected host / pod immediately.".to_string(),
                "Perform memory and forensic log dump.".to_string(),
                "Notify Security Operations Center (SOC) on-call.".to_string(),
            ]
        } else {
            remediation_steps
        };

        let latency = start.elapsed().as_millis();
        if let Some(auditor) = &self.auditor {
            auditor.record(&alert.title, &final_verdict, latency).await;
        }

        Ok(AnalysisReport {
            incident_id: alert.id.clone(),
            title: alert.title.clone(),
            assessed_risk: alert.severity,
            root_cause_analysis: analysis_text,
            relevant_knowledge,
            remediation_steps: final_steps,
            generated_at: Utc::now(),
        })
    }

    /// Direct test of input guardrail rules
    pub async fn test_guardrail_input(&self, input: &str) -> Result<GuardrailVerdict, SentryError> {
        if let Some(guardrail) = &self.guardrail {
            guardrail.inspect_input(input).await
        } else {
            Ok(GuardrailVerdict::safe())
        }
    }

    /// Direct test of output guardrail rules
    pub async fn test_guardrail_output(&self, output: &str, context: &str) -> Result<GuardrailVerdict, SentryError> {
        if let Some(guardrail) = &self.guardrail {
            guardrail.inspect_output(output, context).await
        } else {
            Ok(GuardrailVerdict::safe())
        }
    }
}

