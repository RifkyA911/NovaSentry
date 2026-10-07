use async_trait::async_trait;
use crate::core::error::SentryError;
use crate::core::models::SearchResult;
use crate::core::traits::LlmClient;

/// Formats augmented prompts by injecting retrieved context chunks with citations.
pub struct PromptBuilder;

impl PromptBuilder {
    pub fn build_rag_prompt(query: &str, contexts: &[SearchResult]) -> String {
        let mut context_str = String::new();

        for (i, res) in contexts.iter().enumerate() {
            let title = res
                .chunk
                .metadata
                .get("title")
                .cloned()
                .unwrap_or_else(|| format!("Doc-{}", res.chunk.document_id));

            context_str.push_str(&format!(
                "--- Context [{}] ({}) (Score: {:.3}) ---\n{}\n\n",
                i + 1,
                title,
                res.score,
                res.chunk.content.trim()
            ));
        }

        format!(
            "You are NovaSentry AI, an autonomous cybersecurity incident investigation and triage sentinel.\n\
             Answer the security alert inquiry based SOLELY on the retrieved context below.\n\n\
             [RETRIEVED KNOWLEDGE CONTEXT]\n\
             {}\n\
             [INVESTIGATION QUERY / TELEMETRY]\n\
             {}\n\n\
             Provide a comprehensive assessment including:\n\
             1. Threat Summary\n\
             2. Root Cause Hypothesis\n\
             3. Immediate Containment & Mitigation Actions",
            if context_str.is_empty() { "No prior knowledge documents retrieved." } else { &context_str },
            query
        )
    }
}

/// A lightweight, deterministic Mock LLM client for testing and pseudo-prototyping.
#[derive(Debug, Clone, Default)]
pub struct MockLlmGenerator {
    pub model_name: String,
}

impl MockLlmGenerator {
    pub fn new(model_name: impl Into<String>) -> Self {
        Self {
            model_name: model_name.into(),
        }
    }
}

#[async_trait]
impl LlmClient for MockLlmGenerator {
    fn model_name(&self) -> &str {
        if self.model_name.is_empty() {
            "NovaSentry-Reasoner-v1"
        } else {
            &self.model_name
        }
    }

    async fn generate(&self, prompt: &str, system_context: Option<&str>) -> Result<String, SentryError> {
        let mut response = String::new();

        if let Some(sys) = system_context {
            response.push_str(&format!("[System Policy Active]: {}\n\n", sys));
        }

        response.push_str(&format!(
            "=== NovaSentry Security Synthesis (Model: {}) ===\n",
            if self.model_name.is_empty() { "Nova-Sentry-v1-Proto" } else { &self.model_name }
        ));

        if prompt.contains("SQL Injection") || prompt.contains("sql") {
            response.push_str(
                "• THREAT: High-risk SQL Injection attempt matching known CVE mitigation playbook.\n\
                 • ROOT CAUSE: Unsanitized database parameterization in edge API Gateway route.\n\
                 • ACTION: Activate WAF SQLi block rule, revoke compromised session tokens, patch input validation filter."
            );
        } else if prompt.contains("privilege escalation") || prompt.contains("pod") || prompt.contains("escape") {
            response.push_str(
                "• THREAT: Critical Container Escape / Host Privilege Escalation detected.\n\
                 • ROOT CAUSE: Pod running with privileged securityContext or hostPID access enabled.\n\
                 • ACTION: Quarantine node worker immediately, terminate affected pod namespace, enforce Kyverno/OPA restrictive policy."
            );
        } else {
            response.push_str(
                "• THREAT: Anomalous telemetry pattern observed.\n\
                 • ROOT CAUSE: Investigation underway based on matching knowledge vectors.\n\
                 • ACTION: Restrict endpoint network egress, initiate forensic snapshot, monitor audit logs."
            );
        }

        Ok(response)
    }
}
