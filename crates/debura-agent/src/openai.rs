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
            not extract them and must not invent facts beyond what's given. \
            \n\n\
            Two different kinds of claim matter here, and they are not the same thing. Exactly \
            one hypothesis must use the predicate \"mechanical_behavior\": what the function's \
            own body literally does, at the level the decompilation itself supports (e.g. \
            \"decrementsIntegerField\", \"iterates20x20Grid\", \"comparesTwoStructs\"). Always \
            propose this one, even when nothing else is clear -- it only needs the function's \
            own code. \
            \n\n\
            Separately, propose a hypothesis under the predicate \"semantic_role\" (that literal \
            string, not a paraphrase) ONLY when you have evidence beyond the function's own body \
            -- its callers (the called_by observations), its class membership and what its \
            sibling methods suggest the class is for, or field semantics -- that supports a \
            claim about this function's PURPOSE in the program, not just its mechanics. A real \
            case this matters for: a function that decrements a field is mechanically a \
            decrement, but if it's a Snake method reached from a collision-handling path and \
            leads toward a game-over state, that context is what justifies naming its semantic \
            role something like \"die\" -- the decrement alone does not. If your only evidence is \
            the function's own decompiled body, do not propose a semantic_role at all this round; \
            leaving it unproposed (so the subject keeps its raw name for now) is a more honest \
            outcome than a confident-sounding guess the body alone can't support. This applies \
            just as much when your only alternative is a generic placeholder: a value like \
            \"function\", \"method\", \"handler\", \"process\", or \"logic\" is not a real \
            semantic_role just because some word was needed to fill the field -- it conveys \
            nothing that distinguishes this subject from any other, and is exactly as \
            unsupported as no evidence at all. Omitting semantic_role is always the honest \
            choice over a placeholder like that. When you do have real evidence, semantic_role's \
            value should still be an identifier-style name, e.g. \"calculateDirection\", never a \
            sentence and never a generic placeholder word. semantic_role is the only predicate \
            Debura's C++ recovery step reads to rename anything -- a proposed name under any \
            other predicate (including mechanical_behavior) is invisible to it and the subject \
            keeps its raw, unverified Ghidra name. \
            \n\n\
            Additional hypotheses under other predicates (ownership, purpose, etc.) are welcome \
            and should use whatever predicate best describes that claim. Cite existing \
            hypothesis ids in depends_on only if they appear in the provided list of existing \
            hypotheses. If an existing hypothesis is marked as contested or rejected with a \
            stated reason, do not propose the same claim again -- either address why it failed or \
            propose something genuinely different. If the subject has a vtable_install_pattern \
            observation, its semantic_role should be \"install<ClassName>Vtable\" (e.g. \
            \"installWallVtable\") -- identifier-style, class-qualified, and specific in exactly \
            this sense, without claiming to know constructor vs destructor, which that \
            observation deliberately doesn't determine. If the subject has a \
            sibling_vtable_role observation, a sibling class's own method at the same vtable \
            slot already earned an ACCEPTED semantic_role -- by the Itanium ABI, that slot means \
            the same logical method across every class sharing that ancestor, just with a \
            different override, so this is strong, structural evidence for the same or an \
            analogous role here, not merely another independent guess to weigh equally against \
            everything else. Prefer it unless this subject's own body, callers, or fields \
            actively contradict it. \
            \n\n\
            The \"Call-sequence context\" section shows the nearest labeled call before and after \
            this subject's own call site, inside each caller's own call sequence -- \"nearest\" \
            meaning the search walks outward past unlabeled calls to find one, so it may be more \
            than one call away; the reported distance tells you how far. This is real evidence \
            about the subject's PURPOSE, not just its mechanics, even when nothing dispatches to \
            it polymorphically: a subject called between something a few calls before labeled \
            \"semantic_role: clearsScreen\" and something a few calls after labeled \
            \"semantic_role: updatesScreen\", every frame, is doing the render step regardless of \
            what its own body's loop and arithmetic look like in isolation -- propose a \
            semantic_role at that level (e.g. \"draw\"), not a restatement of the loop itself \
            (e.g. \"populateCells\", \"iteratesGrid\"), when the surrounding calls support it. \
            Weigh distance: immediately-adjacent evidence is stronger than evidence several calls \
            away, and several unrelated intervening calls should make you more cautious, not less. \
            The reverse also holds: don't manufacture this kind of role if the neighbors are \
            unlabeled or unrelated -- an empty or uninformative call-sequence section is not \
            itself evidence of anything.";

        let user = render_analyze_function_task(task);
        let value = self.complete(
            SYSTEM,
            &user,
            "investigation_result",
            investigation_result_schema(),
        )?;
        serde_json::from_value(value).context("mapping OpenAI output to InvestigationResult")
    }

    fn investigate_batch(&self, tasks: &[AnalyzeFunctionTask]) -> Vec<Result<InvestigationResult>> {
        if tasks.is_empty() {
            return Vec::new();
        }
        if tasks.len() == 1 {
            return vec![self.investigate(&tasks[0])];
        }

        const SYSTEM: &str = "You are Debura's AnalyzeFunction reasoning step, batched: you are \
            given several independent subjects from the same binary in one request, each with \
            its own deterministic Ghidra facts. Analyze each one entirely on its own terms -- \
            nothing about one subject bears on another, and evidence must never be borrowed \
            across them. You are given deterministic facts already extracted from a compiled \
            binary by Ghidra -- you did not extract them and must not invent facts beyond \
            what's given. \
            \n\n\
            Two different kinds of claim matter for each subject, and they are not the same \
            thing. Exactly one hypothesis per subject must use the predicate \
            \"mechanical_behavior\": what that subject's own body literally does, at the level \
            the decompilation itself supports (e.g. \"decrementsIntegerField\", \
            \"iterates20x20Grid\"). Always propose this one for every subject, even when nothing \
            else is clear -- it only needs that subject's own code. \
            \n\n\
            Separately, propose a hypothesis under the predicate \"semantic_role\" (that literal \
            string, not a paraphrase) for a given subject ONLY when you have evidence beyond its \
            own body -- its callers (the called_by observations), its class membership and what \
            its sibling methods suggest the class is for, or field semantics -- that supports a \
            claim about that subject's PURPOSE in the program, not just its mechanics. If a \
            subject's only evidence is its own decompiled body, do not propose a semantic_role \
            for it this round; leaving it unproposed is a more honest outcome than a \
            confident-sounding guess the body alone can't support. This applies just as much when \
            your only alternative is a generic placeholder: a value like \"function\", \
            \"method\", \"handler\", \"process\", or \"logic\" is not a real semantic_role just \
            because some word was needed to fill the field -- it conveys nothing that \
            distinguishes that subject from any other, and is exactly as unsupported as no \
            evidence at all. Omitting semantic_role is always the honest choice over a \
            placeholder like that. When you do have real evidence, semantic_role's value should \
            still be an identifier-style name, e.g. \"calculateDirection\", never a sentence and \
            never a generic placeholder word. semantic_role is the only predicate Debura's C++ \
            recovery step reads to rename anything -- a proposed name under any other predicate \
            (including mechanical_behavior) is invisible to it and the subject keeps its raw, \
            unverified Ghidra name. \
            \n\n\
            Additional hypotheses under other predicates (ownership, purpose, etc.) are welcome \
            and should use whatever predicate best describes that claim. Cite existing \
            hypothesis ids in depends_on only if they appear in that subject's own list of \
            existing hypotheses. Leave arrays empty rather than guessing when you have nothing \
            well-founded to add for a subject. If an existing hypothesis is marked as contested \
            or rejected with a stated reason, do not propose the same claim again -- either \
            address why it failed or propose something genuinely different. If a subject has a \
            vtable_install_pattern observation, its semantic_role should be \
            \"install<ClassName>Vtable\" (e.g. \"installWallVtable\") -- identifier-style, \
            class-qualified, and specific in exactly this sense, without claiming to know \
            constructor vs destructor, which that observation deliberately doesn't determine. If \
            a subject has a sibling_vtable_role observation, a sibling class's own method at the \
            same vtable slot already earned an ACCEPTED semantic_role -- by the Itanium ABI, \
            that slot means the same logical method across every class sharing that ancestor, \
            just with a different override, so this is strong, structural evidence for the same \
            or an analogous role here, not merely another independent guess to weigh equally \
            against everything else. Prefer it unless that subject's own body, callers, or \
            fields actively contradict it. \
            \n\n\
            Each subject's \"Call-sequence context\" section shows the nearest labeled call before \
            and after its own call site, inside each caller's own call sequence -- \"nearest\" \
            meaning the search walks outward past unlabeled calls to find one, so it may be more \
            than one call away; the reported distance tells you how far. This is real evidence \
            about that subject's PURPOSE, not just its mechanics, even when nothing dispatches to \
            it polymorphically: a subject called between something a few calls before labeled \
            \"semantic_role: clearsScreen\" and something a few calls after labeled \
            \"semantic_role: updatesScreen\", every frame, is doing the render step regardless of \
            what its own body's loop and arithmetic look like in isolation -- propose a \
            semantic_role at that level (e.g. \"draw\"), not a restatement of the loop itself \
            (e.g. \"populateCells\", \"iteratesGrid\"), when the surrounding calls support it. \
            Weigh distance: immediately-adjacent evidence is stronger than evidence several calls \
            away, and several unrelated intervening calls should make you more cautious, not less. \
            The reverse also holds: don't manufacture this kind of role if a subject's neighbors \
            are unlabeled or unrelated -- an empty or uninformative call-sequence section is not \
            itself evidence of anything. \
            \n\n\
            Return exactly one result per subject listed below, \
            each carrying that subject's own address back so results can be matched up -- order \
            doesn't matter, the subject field is authoritative.";

        let user = render_analyze_function_batch(tasks);
        let value = match self.complete(
            SYSTEM,
            &user,
            "investigation_batch_result",
            investigation_batch_schema(),
        ) {
            Ok(value) => value,
            Err(error) => {
                let message = format!("{error:#}");
                return tasks.iter().map(|_| Err(anyhow::anyhow!(message.clone()))).collect();
            }
        };

        let parsed: BatchResponse = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                let message = format!("mapping OpenAI output to a batch of InvestigationResult: {error:#}");
                return tasks.iter().map(|_| Err(anyhow::anyhow!(message.clone()))).collect();
            }
        };

        let mut by_subject: std::collections::HashMap<String, InvestigationResult> = parsed
            .results
            .into_iter()
            .map(|entry| (entry.subject, entry.investigation))
            .collect();

        tasks
            .iter()
            .map(|task| {
                by_subject
                    .remove(&task.subject)
                    .ok_or_else(|| anyhow::anyhow!("model omitted a result for subject {}", task.subject))
            })
            .collect()
    }

    fn challenge(&self, task: &ChallengeHypothesisTask) -> Result<ChallengeResult> {
        let value = self.complete(
            CHALLENGE_SYSTEM,
            &render_challenge_task(task),
            "challenge_result",
            challenge_result_schema(),
        )?;
        serde_json::from_value(value).context("mapping OpenAI output to ChallengeResult")
    }

    fn challenge_batch(&self, tasks: &[ChallengeHypothesisTask]) -> Vec<Result<ChallengeResult>> {
        if tasks.is_empty() {
            return Vec::new();
        }
        if tasks.len() == 1 {
            return vec![self.challenge(&tasks[0])];
        }

        const SYSTEM: &str = "You are Debura's ChallengeHypothesis adversarial verification \
            step, batched: you are given several independent hypotheses in one request, each \
            with its own evidence and observations. Judge each one entirely on its own terms -- \
            a contradiction, alternative explanation, or doubt found for one hypothesis must \
            never be reused or referenced against another; treat each as if it were the only \
            one in the request. Your objective for each is NOT to find more evidence that the \
            hypothesis is right -- it is to actively try to prove it wrong. Look for: \
            contradicting evidence, a more general or more plausible alternative explanation, \
            or reasons to doubt the current confidence. If a genuine, careful attempt finds \
            nothing wrong with a given hypothesis, say so honestly for that one rather than \
            manufacturing a finding. If your alternative for a hypothesis is itself a better \
            name for its subject, its predicate must be the literal string \"semantic_role\" \
            (matching the convention AnalyzeFunction uses) -- Debura's C++ recovery step only \
            reads that exact predicate to name anything. If it's some other kind of claim, use \
            whatever predicate best fits. Return exactly one result per hypothesis listed \
            below, each carrying that hypothesis's own id back so results can be matched up -- \
            order doesn't matter, the hypothesis field is authoritative.";

        let user = render_challenge_batch(tasks);
        let value = match self.complete(
            SYSTEM,
            &user,
            "challenge_batch_result",
            challenge_batch_schema(),
        ) {
            Ok(value) => value,
            Err(error) => {
                let message = format!("{error:#}");
                return tasks.iter().map(|_| Err(anyhow::anyhow!(message.clone()))).collect();
            }
        };

        let parsed: ChallengeBatchResponse = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                let message = format!("mapping OpenAI output to a batch of ChallengeResult: {error:#}");
                return tasks.iter().map(|_| Err(anyhow::anyhow!(message.clone()))).collect();
            }
        };

        let mut by_hypothesis: std::collections::HashMap<u64, ChallengeResult> = parsed
            .results
            .into_iter()
            .map(|entry| (entry.hypothesis, entry.result))
            .collect();

        tasks
            .iter()
            .map(|task| {
                let id = task.hypothesis.id.0;
                by_hypothesis
                    .remove(&id)
                    .ok_or_else(|| anyhow::anyhow!("model omitted a result for hypothesis H{id}"))
            })
            .collect()
    }

    fn resolve_contradiction(&self, task: &ResolveContradictionTask) -> Result<ResolutionResult> {
        let value = self.complete(
            RESOLVE_SYSTEM,
            &render_resolve_task(task),
            "resolution_result",
            resolution_result_schema(),
        )?;
        let raw: RawResolution =
            serde_json::from_value(value).context("mapping OpenAI output to ResolutionResult")?;
        parse_resolution(raw, task.hypothesis.confidence)
    }

    fn resolve_batch(&self, tasks: &[ResolveContradictionTask]) -> Vec<Result<ResolutionResult>> {
        if tasks.is_empty() {
            return Vec::new();
        }
        if tasks.len() == 1 {
            return vec![self.resolve_contradiction(&tasks[0])];
        }

        const SYSTEM: &str = "You are Debura's ResolveContradiction step, batched: you are \
            given several independent CONTESTED hypotheses in one request, each with its own \
            supporting and contradicting evidence. Judge each one entirely on its own terms -- \
            reasoning about one hypothesis's evidence must never be reused or referenced when \
            judging another; treat each as if it were the only one in the request. For each, \
            weigh its supporting evidence against its contradicting evidence and decide whether \
            the contradiction actually holds up, or can be explained away. Return exactly one \
            result per hypothesis listed below, each carrying that hypothesis's own id back so \
            results can be matched up -- order doesn't matter, the hypothesis field is \
            authoritative.";

        let user = render_resolve_batch(tasks);
        let value = match self.complete(
            SYSTEM,
            &user,
            "resolution_batch_result",
            resolution_batch_schema(),
        ) {
            Ok(value) => value,
            Err(error) => {
                let message = format!("{error:#}");
                return tasks.iter().map(|_| Err(anyhow::anyhow!(message.clone()))).collect();
            }
        };

        let parsed: ResolutionBatchResponse = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                let message = format!("mapping OpenAI output to a batch of ResolutionResult: {error:#}");
                return tasks.iter().map(|_| Err(anyhow::anyhow!(message.clone()))).collect();
            }
        };

        let mut by_hypothesis: std::collections::HashMap<u64, RawResolution> = parsed
            .results
            .into_iter()
            .map(|entry| (entry.hypothesis, entry.result))
            .collect();

        tasks
            .iter()
            .map(|task| {
                let id = task.hypothesis.id.0;
                let raw = by_hypothesis
                    .remove(&id)
                    .ok_or_else(|| anyhow::anyhow!("model omitted a result for hypothesis H{id}"))?;
                parse_resolution(raw, task.hypothesis.confidence)
            })
            .collect()
    }
}

const CHALLENGE_SYSTEM: &str = "You are Debura's ChallengeHypothesis adversarial verification \
    step. Your objective is NOT to find more evidence that the hypothesis is right -- it is to \
    actively try to prove it wrong. Look for: contradicting evidence, a more general or more \
    plausible alternative explanation, or reasons to doubt the current confidence. If a \
    genuine, careful attempt finds nothing wrong, say so honestly rather than manufacturing a \
    finding. If your alternative is itself a better name for the subject, its predicate must be \
    the literal string \"semantic_role\" (matching the convention AnalyzeFunction uses) -- \
    Debura's C++ recovery step only reads that exact predicate to name anything. If it's some \
    other kind of claim, use whatever predicate best fits. A subject with a \
    vtable_install_pattern observation is known, structurally, to store its class's own vtable \
    pointer -- a semantic_role name shaped \"install<ClassName>Vtable\" is already an \
    appropriately conservative, honest name for exactly that fact, not a vague placeholder \
    needing more specificity; don't demand it also specify constructor vs destructor or a \
    fuller behavioral role the evidence doesn't support. Likewise, a subject with a \
    sibling_vtable_role observation is being named by analogy to a sibling class's own ACCEPTED \
    role at the same vtable slot -- a real, structural signal (the Itanium ABI guarantees that \
    slot means the same logical method across the hierarchy), not an unsupported guess just \
    because it wasn't independently re-derived from this subject's own body alone. Judge it the \
    same way you'd judge any other well-evidenced claim: look for a genuine reason the analogy \
    doesn't hold here (a body, caller, or field pattern that contradicts it), not for the \
    analogy's mere existence. \
    \n\n\
    If the hypothesis under review has the predicate \"semantic_role\" (not \
    \"mechanical_behavior\" -- that one is expected to describe the body's own mechanics and \
    isn't held to this bar), ask specifically: could this be describing only one internal side \
    effect or mechanical detail of the function, rather than its role in the application? A real \
    case this caught: a semantic_role of \"decrementValue\" for a Snake method later shown to be \
    the death handler -- the decrement is real, but naming the *role* after one incidental \
    operation, with no supporting evidence beyond the function's own body (no caller, class-role, \
    or field-semantics context contributing), is exactly the failure this question exists to \
    catch. If that's what you find -- a semantic_role whose only support is the subject's own \
    decompiled body, describing what the code does rather than why it exists -- flag it as a \
    contradiction and recommend it be withdrawn (or re-proposed under mechanical_behavior \
    instead), even when the description is technically accurate. \
    \n\n\
    Also reject, unconditionally, a semantic_role value that is a generic placeholder word \
    rather than a real name -- \"function\", \"method\", \"handler\", \"process\", \"logic\", or \
    anything similarly generic. A real case this caught: \"function\" accepted as a subject's \
    semantic_role -- technically not *false* (it is, trivially, a function), but conveying \
    nothing that distinguishes that subject from any other one in the binary, which makes it \
    exactly as useless as no semantic_role at all while looking like real recovered knowledge. \
    This check doesn't depend on the vaguer side-effect question above -- a placeholder like this \
    fails even if there happens to be real supporting evidence behind it, because the *name* \
    itself carries no information regardless of what justified proposing it.";

const RESOLVE_SYSTEM: &str = "You are Debura's ResolveContradiction step. A hypothesis has been \
    marked CONTESTED because contradicting evidence was found. Weigh the supporting evidence \
    against the contradicting evidence and decide whether the contradiction actually holds up, \
    or can be explained away. \
    \n\n\
    Contradicting evidence sourced from \"debura:mechanical_shape_check\" is not a free-form \
    guess -- it's a deterministic finding that the hypothesis's semantic_role value contains no \
    word that isn't already in this same subject's own mechanical_behavior value, i.e. the name \
    is, by construction, a restatement of mechanism rather than an independent claim about the \
    function's role. Don't let it survive just because a sibling class independently agreed on \
    the same word (sibling agreement on a restated-mechanism name is still a restated-mechanism \
    name for all of them, not corroboration) or because the confidence number is high (the \
    number reflects how sure the model was, not whether the word choice itself says anything \
    beyond mechanism). Only let it survive if the supporting evidence adds something this check \
    couldn't see -- a caller's own purpose, a field-access pattern, or another structural fact \
    that gives the value a claim beyond what the subject's own body mechanically does.";

/// Shared by the single and batched ResolveContradiction paths: maps the
/// wire-shape `RawResolution` onto the real `Resolution` enum (a payload
/// on one variant doesn't map onto a clean JSON Schema the way a plain
/// struct does, so this is asked for separately and converted here).
fn parse_resolution(raw: RawResolution, fallback_confidence: f64) -> Result<ResolutionResult> {
    let resolution = match raw.resolution.as_str() {
        "survives" => Resolution::Survives {
            confidence: raw.confidence.unwrap_or(fallback_confidence),
        },
        "rejected" => Resolution::Rejected,
        other => bail!("unexpected resolution verdict from model: {other}"),
    };

    Ok(ResolutionResult {
        resolution,
        reasoning: raw.reasoning,
    })
}

/// `Resolution` is a Rust enum with a payload on one variant, which doesn't
/// map onto a clean JSON Schema the way a plain struct does -- this is the
/// wire shape we actually ask the model for, mapped onto `Resolution`
/// afterward.
#[derive(Debug, Deserialize)]
struct RawResolution {
    resolution: String,
    confidence: Option<f64>,
    reasoning: String,
}

fn render_analyze_function_batch(tasks: &[AnalyzeFunctionTask]) -> String {
    let mut out = format!("{} subjects follow, each independent:\n\n", tasks.len());
    for task in tasks {
        out.push_str("=====\n");
        out.push_str(&render_analyze_function_task(task));
        out.push('\n');
    }
    out
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

    out.push_str("\nCall-sequence context:\n");
    if task.call_sequence.is_empty() {
        out.push_str("(no recorded caller, or no decompiled body for its caller)\n");
    }
    for neighbor in &task.call_sequence {
        let describe = |c: &crate::call_context::SequencedCall| {
            let position = if c.distance == 1 {
                "immediately".to_string()
            } else {
                format!("{} calls", c.distance)
            };
            match &c.best_known_label {
                Some(label) => format!("{position} away: {} ({label})", c.address),
                None => format!("{position} away: {} (unlabeled)", c.address),
            }
        };
        out.push_str(&format!(
            "- inside caller {}: before it, {}; after it, {}\n",
            neighbor.caller,
            neighbor.before.as_ref().map(describe).unwrap_or_else(|| "nothing -- first call in this caller".to_string()),
            neighbor.after.as_ref().map(describe).unwrap_or_else(|| "nothing -- last call in this caller".to_string()),
        ));
    }

    out
}

fn render_challenge_batch(tasks: &[ChallengeHypothesisTask]) -> String {
    let mut out = format!("{} hypotheses follow, each independent:\n\n", tasks.len());
    for task in tasks {
        out.push_str("=====\n");
        out.push_str(&render_challenge_task(task));
        out.push('\n');
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

fn render_resolve_batch(tasks: &[ResolveContradictionTask]) -> String {
    let mut out = format!("{} contested hypotheses follow, each independent:\n\n", tasks.len());
    for task in tasks {
        out.push_str("=====\n");
        out.push_str(&render_resolve_task(task));
        out.push('\n');
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

/// One `{results: [...]}` entry as OpenAI returns it, paired with the
/// subject it belongs to so the flat response can be matched back up to
/// whichever `AnalyzeFunctionTask` asked for it.
#[derive(Debug, Deserialize)]
struct BatchEntry {
    subject: String,
    investigation: InvestigationResult,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    results: Vec<BatchEntry>,
}

fn investigation_batch_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "subject": {"type": "string"},
                        "investigation": investigation_result_schema()
                    },
                    "required": ["subject", "investigation"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["results"],
        "additionalProperties": false
    })
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

/// One `{results: [...]}` entry as OpenAI returns it, paired with the
/// hypothesis id it belongs to so the flat response can be matched back
/// up to whichever `ChallengeHypothesisTask` asked for it.
#[derive(Debug, Deserialize)]
struct ChallengeBatchEntry {
    hypothesis: u64,
    #[serde(flatten)]
    result: ChallengeResult,
}

#[derive(Debug, Deserialize)]
struct ChallengeBatchResponse {
    results: Vec<ChallengeBatchEntry>,
}

fn challenge_batch_schema() -> Value {
    let mut entry_schema = challenge_result_schema();
    entry_schema["properties"]["hypothesis"] = json!({"type": "integer"});
    entry_schema["required"]
        .as_array_mut()
        .expect("challenge_result_schema always has a required array")
        .push(json!("hypothesis"));

    json!({
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": entry_schema
            }
        },
        "required": ["results"],
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

/// One `{results: [...]}` entry as OpenAI returns it, paired with the
/// hypothesis id it belongs to so the flat response can be matched back
/// up to whichever `ResolveContradictionTask` asked for it.
#[derive(Debug, Deserialize)]
struct ResolutionBatchEntry {
    hypothesis: u64,
    #[serde(flatten)]
    result: RawResolution,
}

#[derive(Debug, Deserialize)]
struct ResolutionBatchResponse {
    results: Vec<ResolutionBatchEntry>,
}

fn resolution_batch_schema() -> Value {
    let mut entry_schema = resolution_result_schema();
    entry_schema["properties"]["hypothesis"] = json!({"type": "integer"});
    entry_schema["required"]
        .as_array_mut()
        .expect("resolution_result_schema always has a required array")
        .push(json!("hypothesis"));

    json!({
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": entry_schema
            }
        },
        "required": ["results"],
        "additionalProperties": false
    })
}
