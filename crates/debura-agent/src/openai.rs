//! A real `AgentProvider` backed by OpenAI's Chat Completions API, using
//! Structured Outputs (`response_format: json_schema`, strict mode) so the
//! model's reply is guaranteed to parse into our result types rather than
//! needing fragile prompt-based JSON extraction.
//!
//! Behind the `openai` feature so crates that only need the mock provider
//! (most of the test suite) don't pay for `reqwest` in their build.

use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::challenge::{ChallengeHypothesisTask, ChallengeResult};
use crate::resolution::{Resolution, ResolutionResult, ResolveContradictionTask};
use crate::result::InvestigationResult;
use crate::task::AnalyzeFunctionTask;
use crate::AgentProvider;

const API_URL: &str = "https://api.openai.com/v1/chat/completions";
const DEFAULT_MODEL: &str = "gpt-4o-mini";

/// PROJECT.md M10: at real concurrency, 429 (rate limit) responses aren't
/// exceptional -- they're expected, and OpenAI's guidance is to back off
/// and retry, not fail immediately. 5xx are treated the same way (also
/// transient). Any other status is a real error and isn't retried.
const MAX_RETRIES: u32 = 6;
const INITIAL_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct OpenAiProvider {
    api_key: String,
    model: String,
    client: reqwest::blocking::Client,
}

impl OpenAiProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_model(api_key, DEFAULT_MODEL)
    }

    pub fn with_model(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            model: model.into(),
            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn from_env() -> Result<Self> {
        let key = std::env::var("OPENAI_API_KEY").context(
            "OPENAI_API_KEY is not set (put it in .env at the repo root, or export it)",
        )?;
        Ok(Self::new(key))
    }

    fn complete(&self, system: &str, user: &str, schema_name: &str, schema: Value) -> Result<Value> {
        let body = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "strict": true,
                    "schema": schema,
                }
            }
        });

        let mut attempt = 0u32;
        loop {
            let response = self
                .client
                .post(API_URL)
                .bearer_auth(&self.api_key)
                .json(&body)
                .send()
                .context("OpenAI request failed")?;

            let status = response.status();
            let retryable = status.as_u16() == 429 || status.is_server_error();

            if retryable && attempt < MAX_RETRIES {
                let wait = retry_after(&response).unwrap_or_else(|| backoff_for(attempt));
                tracing::warn!(
                    %status,
                    attempt,
                    wait_ms = wait.as_millis() as u64,
                    "OpenAI request throttled, retrying"
                );
                thread::sleep(wait);
                attempt += 1;
                continue;
            }

            let text = response.text().context("reading OpenAI response body")?;
            if !status.is_success() {
                bail!("OpenAI API error ({status}) after {attempt} retries: {text}");
            }

            let parsed: Value =
                serde_json::from_str(&text).context("parsing OpenAI response envelope")?;
            let content = parsed["choices"][0]["message"]["content"]
                .as_str()
                .context("OpenAI response missing message content")?;

            return serde_json::from_str(content).context("parsing structured output JSON");
        }
    }
}

/// Prefers the server's own `Retry-After` header over guessing.
fn retry_after(response: &reqwest::blocking::Response) -> Option<Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn backoff_for(attempt: u32) -> Duration {
    let millis = INITIAL_BACKOFF.as_millis() as u64 * 2u64.saturating_pow(attempt);
    Duration::from_millis(millis).min(MAX_BACKOFF)
}

impl AgentProvider for OpenAiProvider {
    fn investigate(&self, task: &AnalyzeFunctionTask) -> Result<InvestigationResult> {
        const SYSTEM: &str = "You are Debura's AnalyzeFunction reasoning step. You are given \
            deterministic facts already extracted from a compiled binary by Ghidra -- you did \
            not extract them and must not invent facts beyond what's given. Propose hypotheses \
            about the semantic role of the given subject only. Cite existing hypothesis ids in \
            depends_on only if they appear in the provided list of existing hypotheses. Leave \
            arrays empty rather than guessing when you have nothing well-founded to add. If an \
            existing hypothesis is marked as contested or rejected with a stated reason, do not \
            propose the same claim again -- either address why it failed or propose something \
            genuinely different.";

        let user = render_analyze_function_task(task);
        let value = self.complete(
            SYSTEM,
            &user,
            "investigation_result",
            investigation_result_schema(),
        )?;
        serde_json::from_value(value).context("mapping OpenAI output to InvestigationResult")
    }

    fn challenge(&self, task: &ChallengeHypothesisTask) -> Result<ChallengeResult> {
        const SYSTEM: &str = "You are Debura's ChallengeHypothesis adversarial verification \
            step. Your objective is NOT to find more evidence that the hypothesis is right -- \
            it is to actively try to prove it wrong. Look for: contradicting evidence, a more \
            general or more plausible alternative explanation, or reasons to doubt the current \
            confidence. If a genuine, careful attempt finds nothing wrong, say so honestly \
            rather than manufacturing a finding.";

        let user = render_challenge_task(task);
        let value = self.complete(SYSTEM, &user, "challenge_result", challenge_result_schema())?;
        serde_json::from_value(value).context("mapping OpenAI output to ChallengeResult")
    }

    fn resolve_contradiction(&self, task: &ResolveContradictionTask) -> Result<ResolutionResult> {
        const SYSTEM: &str = "You are Debura's ResolveContradiction step. A hypothesis has been \
            marked CONTESTED because contradicting evidence was found. Weigh the supporting \
            evidence against the contradicting evidence and decide whether the contradiction \
            actually holds up, or can be explained away.";

        let user = render_resolve_task(task);
        let value = self.complete(
            SYSTEM,
            &user,
            "resolution_result",
            resolution_result_schema(),
        )?;

        let raw: RawResolution =
            serde_json::from_value(value).context("mapping OpenAI output to ResolutionResult")?;

        let resolution = match raw.resolution.as_str() {
            "survives" => Resolution::Survives {
                confidence: raw.confidence.unwrap_or(task.hypothesis.confidence),
            },
            "rejected" => Resolution::Rejected,
            other => bail!("unexpected resolution verdict from model: {other}"),
        };

        Ok(ResolutionResult {
            resolution,
            reasoning: raw.reasoning,
        })
    }
}

/// `Resolution` is a Rust enum with a payload on one variant, which doesn't
/// map onto a clean JSON Schema the way a plain struct does -- this is the
/// wire shape we actually ask the model for, mapped onto `Resolution`
/// afterward.
#[derive(Deserialize)]
struct RawResolution {
    resolution: String,
    confidence: Option<f64>,
    reasoning: String,
}

fn render_analyze_function_task(task: &AnalyzeFunctionTask) -> String {
    let mut out = format!("Subject: {}\n\nKnown observations:\n", task.subject);
    for o in &task.observations {
        out.push_str(&format!(
            "- {} {} = {} (confidence {:.2}, source {})\n",
            o.subject, o.predicate, o.value, o.confidence, o.source
        ));
    }

    out.push_str("\nExisting hypotheses about this subject:\n");
    if task.existing_hypotheses.is_empty() {
        out.push_str("(none)\n");
    }
    for h in &task.existing_hypotheses {
        out.push_str(&format!(
            "- {}: {} = {} (confidence {:.2}, status {:?})\n",
            h.id, h.predicate, h.value, h.confidence, h.status
        ));
        if let Some(reasons) = task.rejection_reasons.get(&h.id) {
            for reason in reasons {
                out.push_str(&format!("    this was contested/rejected because: {reason}\n"));
            }
        }
    }

    out
}

fn render_challenge_task(task: &ChallengeHypothesisTask) -> String {
    let h = &task.hypothesis;
    let mut out = format!(
        "Hypothesis {}: {} {} = {} (confidence {:.2}, status {:?})\n\nSupporting evidence:\n",
        h.id, h.subject, h.predicate, h.value, h.confidence, h.status
    );
    for (evidence, observation) in &task.supporting_evidence {
        out.push_str(&format!(
            "- {} ({}): {} {} = {}\n",
            evidence.relevance, evidence.source, observation.subject, observation.predicate, observation.value
        ));
    }

    out.push_str("\nAll other observations about this subject:\n");
    for o in &task.other_observations {
        out.push_str(&format!(
            "- {} {} = {} (confidence {:.2})\n",
            o.subject, o.predicate, o.value, o.confidence
        ));
    }

    out
}

fn render_resolve_task(task: &ResolveContradictionTask) -> String {
    let h = &task.hypothesis;
    let mut out = format!(
        "Hypothesis {}: {} {} = {} (confidence {:.2}, status {:?})\n\nSupporting evidence:\n",
        h.id, h.subject, h.predicate, h.value, h.confidence, h.status
    );
    for (evidence, observation) in &task.supporting_evidence {
        out.push_str(&format!(
            "- {} ({}): {} {} = {}\n",
            evidence.relevance, evidence.source, observation.subject, observation.predicate, observation.value
        ));
    }

    out.push_str("\nContradicting evidence:\n");
    for (evidence, observation) in &task.contradicting_evidence {
        out.push_str(&format!(
            "- {} ({}): {} {} = {}\n",
            evidence.relevance, evidence.source, observation.subject, observation.predicate, observation.value
        ));
    }

    out
}

fn investigation_result_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "observations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "subject": {"type": "string"},
                        "predicate": {"type": "string"},
                        "value": {"type": "string"},
                        "confidence": {"type": "number"},
                        "source": {"type": "string"}
                    },
                    "required": ["subject", "predicate", "value", "confidence", "source"],
                    "additionalProperties": false
                }
            },
            "hypotheses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "predicate": {"type": "string"},
                        "value": {"type": "string"},
                        "confidence": {"type": "number"},
                        "depends_on": {"type": "array", "items": {"type": "integer"}}
                    },
                    "required": ["predicate", "value", "confidence", "depends_on"],
                    "additionalProperties": false
                }
            },
            "confidence_updates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "hypothesis": {"type": "integer"},
                        "confidence": {"type": "number"}
                    },
                    "required": ["hypothesis", "confidence"],
                    "additionalProperties": false
                }
            },
            "contradictions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "hypothesis": {"type": "integer"},
                        "reason": {"type": "string"}
                    },
                    "required": ["hypothesis", "reason"],
                    "additionalProperties": false
                }
            },
            "followup_tasks": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["observations", "hypotheses", "confidence_updates", "contradictions", "followup_tasks"],
        "additionalProperties": false
    })
}

fn challenge_result_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "contradiction": {"type": ["string", "null"]},
            "alternative": {
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "properties": {
                            "predicate": {"type": "string"},
                            "value": {"type": "string"},
                            "confidence": {"type": "number"},
                            "depends_on": {"type": "array", "items": {"type": "integer"}}
                        },
                        "required": ["predicate", "value", "confidence", "depends_on"],
                        "additionalProperties": false
                    }
                ]
            },
            "confidence_recommendation": {"type": ["number", "null"]},
            "reasoning": {"type": "string"}
        },
        "required": ["contradiction", "alternative", "confidence_recommendation", "reasoning"],
        "additionalProperties": false
    })
}

fn resolution_result_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "resolution": {"type": "string", "enum": ["survives", "rejected"]},
            "confidence": {"type": ["number", "null"]},
            "reasoning": {"type": "string"}
        },
        "required": ["resolution", "confidence", "reasoning"],
        "additionalProperties": false
    })
}
