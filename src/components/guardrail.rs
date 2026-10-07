use async_trait::async_trait;
use crate::core::error::SentryError;
use crate::core::traits::{GuardrailValidator, GuardrailVerdict};

/// Guardrail engine for NovaSentry: protects against prompt injections, secret leakage, and adversarial tampering.
#[derive(Clone)]
pub struct NovaGuardrail {
    injection_patterns: Vec<&'static str>,
    secret_patterns: Vec<&'static str>,
}

impl Default for NovaGuardrail {
    fn default() -> Self {
        Self {
            injection_patterns: vec![
                "ignore previous instructions",
                "disregard all instructions",
                "system prompt reveal",
                "jailbreak",
                "dan mode",
                "bypass policy",
                "sudo mode",
                "show hidden prompt",
            ],
            secret_patterns: vec![
                "sk-proj-",
                "Bearer eyJ",
                "-----BEGIN PRIVATE KEY-----",
                "aws_secret_access_key",
            ],
        }
    }
}

impl NovaGuardrail {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl GuardrailValidator for NovaGuardrail {
    async fn inspect_input(&self, input: &str) -> Result<GuardrailVerdict, SentryError> {
        let input_lower = input.to_lowercase();
        let mut flags = Vec::new();

        for pattern in &self.injection_patterns {
            if input_lower.contains(pattern) {
                flags.push(format!("InjectionPatternDetected: '{}'", pattern));
            }
        }

        if !flags.is_empty() {
            return Ok(GuardrailVerdict::violation(
                flags,
                "Query blocked: detected prompt injection or adversarial instruction manipulation.",
            ));
        }

        Ok(GuardrailVerdict::safe())
    }

    async fn inspect_output(&self, output: &str, _context: &str) -> Result<GuardrailVerdict, SentryError> {
        let mut flags = Vec::new();

        for pattern in &self.secret_patterns {
            if output.contains(pattern) {
                flags.push(format!("SecretLeakDetected: '{}'", pattern));
            }
        }

        if !flags.is_empty() {
            return Ok(GuardrailVerdict::violation(
                flags,
                "Output blocked: potential credential or secret exposure detected.",
            ));
        }

        Ok(GuardrailVerdict::safe())
    }
}
