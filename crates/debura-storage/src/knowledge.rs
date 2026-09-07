//! Persists a `debura_knowledge::KnowledgeGraph` to and from `project.sqlite`
//! (PROJECT.md M3). Each `save` is a full transactional snapshot rather than
//! an incremental diff -- simple and correct, and fast enough until a real
//! scheduler (M6) makes full-graph rewrites a bottleneck.
//!
//! Investigations are persisted with array fields (tool_calls, the various
//! id lists) as JSON columns rather than junction tables, same pragmatic
//! choice as hypotheses' evidence lists -- nothing needs to SQL-query into
//! them yet, only read a whole record back.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use debura_knowledge::{
    Dependency, DependencyKind, Evidence, EvidenceId, Hypothesis, HypothesisId, HypothesisStatus,
    Investigation, InvestigationId, KnowledgeGraph, Observation, ObservationId,
};
use rusqlite::{params, Connection};

pub fn save(conn: &Connection, graph: &KnowledgeGraph) -> Result<()> {
    let tx = conn.unchecked_transaction()?;

    tx.execute("DELETE FROM investigations", [])?;
    tx.execute("DELETE FROM dependencies", [])?;
    tx.execute("DELETE FROM hypotheses", [])?;
    tx.execute("DELETE FROM evidence", [])?;
    tx.execute("DELETE FROM observations", [])?;

    for o in graph.observations() {
        tx.execute(
            "INSERT INTO observations (id, subject, predicate, value, confidence, source, artifact, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                o.id.0,
                o.subject,
                o.predicate,
                o.value,
                o.confidence,
                o.source,
                o.artifact,
                o.created_at.to_rfc3339(),
            ],
        )?;
    }

    for e in graph.all_evidence() {
        tx.execute(
            "INSERT INTO evidence (id, observation_id, relevance, source, location, artifact_reference)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                e.id.0,
                e.observation_id.0,
                e.relevance,
                e.source,
                e.location,
                e.artifact_reference,
            ],
        )?;
    }

    for h in graph.hypotheses() {
        let supporting = ids_to_json(&h.supporting_evidence);
        let contradicting = ids_to_json(&h.contradicting_evidence);
        tx.execute(
            "INSERT INTO hypotheses
                (id, subject, predicate, value, confidence, status,
                 supporting_evidence, contradicting_evidence,
                 created_by, created_at, updated_at, last_verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                h.id.0,
                h.subject,
                h.predicate,
                h.value,
                h.confidence,
                status_to_str(h.status),
                supporting,
                contradicting,
                h.created_by.map(|id| id.0),
                h.created_at.to_rfc3339(),
                h.updated_at.to_rfc3339(),
                h.last_verified_at.map(|t| t.to_rfc3339()),
            ],
        )?;
    }

    for d in graph.dependencies() {
        tx.execute(
            "INSERT INTO dependencies (source_hypothesis, target_hypothesis, kind)
             VALUES (?1, ?2, ?3)",
            params![d.source.0, d.target.0, kind_to_str(d.kind)],
        )?;
    }

    for i in graph.investigations() {
        tx.execute(
            "INSERT INTO investigations
                (id, task, target, context_snapshot, tool_calls, observations,
                 hypotheses_created, hypotheses_modified, evidence_created,
                 result, followup_tasks, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                i.id.0,
                i.task,
                i.target,
                i.context_snapshot,
                strings_to_json(&i.tool_calls),
                obs_ids_to_json(&i.observations),
                hyp_ids_to_json(&i.hypotheses_created),
                hyp_ids_to_json(&i.hypotheses_modified),
                ids_to_json(&i.evidence_created),
                i.result,
                strings_to_json(&i.followup_tasks),
                i.created_at.to_rfc3339(),
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

pub fn load(conn: &Connection) -> Result<KnowledgeGraph> {
    let mut graph = KnowledgeGraph::new();

    let mut stmt = conn.prepare(
        "SELECT id, subject, predicate, value, confidence, source, artifact, created_at
         FROM observations",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, f64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, subject, predicate, value, confidence, source, artifact, created_at) in rows {
        graph.insert_observation(Observation {
            id: ObservationId(id as u64),
            subject,
            predicate,
            value,
            confidence,
            source,
            artifact,
            created_at: parse_dt(&created_at)?,
        });
    }

    let mut stmt = conn.prepare(
        "SELECT id, observation_id, relevance, source, location, artifact_reference FROM evidence",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, observation_id, relevance, source, location, artifact_reference) in rows {
        graph.insert_evidence(Evidence {
            id: EvidenceId(id as u64),
            observation_id: ObservationId(observation_id as u64),
            relevance,
            source,
            location,
            artifact_reference,
        });
    }

    let mut stmt = conn.prepare(
        "SELECT id, subject, predicate, value, confidence, status,
                supporting_evidence, contradicting_evidence,
                created_by, created_at, updated_at, last_verified_at
         FROM hypotheses",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, f64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (
        id,
        subject,
        predicate,
        value,
        confidence,
        status,
        supporting,
        contradicting,
        created_by,
        created_at,
        updated_at,
        last_verified_at,
    ) in rows
    {
        graph.insert_hypothesis(Hypothesis {
            id: HypothesisId(id as u64),
            subject,
            predicate,
            value,
            confidence,
            status: status_from_str(&status)?,
            supporting_evidence: ids_from_json(&supporting)?,
            contradicting_evidence: ids_from_json(&contradicting)?,
            dependencies: Vec::new(), // rebuilt below from the dependencies table
            created_by: created_by.map(|id| InvestigationId(id as u64)),
            created_at: parse_dt(&created_at)?,
            updated_at: parse_dt(&updated_at)?,
            last_verified_at: last_verified_at.as_deref().map(parse_dt).transpose()?,
        });
    }

    let mut stmt =
        conn.prepare("SELECT source_hypothesis, target_hypothesis, kind FROM dependencies")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (source, target, kind) in rows {
        graph.insert_dependency(Dependency {
            source: HypothesisId(source as u64),
            target: HypothesisId(target as u64),
            kind: kind_from_str(&kind)?,
        });
    }

    let mut stmt = conn.prepare(
        "SELECT id, task, target, context_snapshot, tool_calls, observations,
                hypotheses_created, hypotheses_modified, evidence_created,
                result, followup_tasks, created_at
         FROM investigations",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (
        id,
        task,
        target,
        context_snapshot,
        tool_calls,
        observations,
        hypotheses_created,
        hypotheses_modified,
        evidence_created,
        result,
        followup_tasks,
        created_at,
    ) in rows
    {
        graph.insert_investigation(Investigation {
            id: InvestigationId(id as u64),
            task,
            target,
            context_snapshot,
            tool_calls: strings_from_json(&tool_calls)?,
            observations: obs_ids_from_json(&observations)?,
            hypotheses_created: hyp_ids_from_json(&hypotheses_created)?,
            hypotheses_modified: hyp_ids_from_json(&hypotheses_modified)?,
            evidence_created: ids_from_json(&evidence_created)?,
            result,
            followup_tasks: strings_from_json(&followup_tasks)?,
            created_at: parse_dt(&created_at)?,
        });
    }

    Ok(graph)
}

fn ids_to_json(ids: &[EvidenceId]) -> String {
    let raw: Vec<u64> = ids.iter().map(|id| id.0).collect();
    serde_json::to_string(&raw).expect("Vec<u64> always serializes")
}

fn ids_from_json(json: &str) -> Result<Vec<EvidenceId>> {
    let raw: Vec<u64> = serde_json::from_str(json)?;
    Ok(raw.into_iter().map(EvidenceId).collect())
}

fn obs_ids_to_json(ids: &[ObservationId]) -> String {
    let raw: Vec<u64> = ids.iter().map(|id| id.0).collect();
    serde_json::to_string(&raw).expect("Vec<u64> always serializes")
}

fn obs_ids_from_json(json: &str) -> Result<Vec<ObservationId>> {
    let raw: Vec<u64> = serde_json::from_str(json)?;
    Ok(raw.into_iter().map(ObservationId).collect())
}

fn hyp_ids_to_json(ids: &[HypothesisId]) -> String {
    let raw: Vec<u64> = ids.iter().map(|id| id.0).collect();
    serde_json::to_string(&raw).expect("Vec<u64> always serializes")
}

fn hyp_ids_from_json(json: &str) -> Result<Vec<HypothesisId>> {
    let raw: Vec<u64> = serde_json::from_str(json)?;
    Ok(raw.into_iter().map(HypothesisId).collect())
}

fn strings_to_json(items: &[String]) -> String {
    serde_json::to_string(items).expect("Vec<String> always serializes")
}

fn strings_from_json(json: &str) -> Result<Vec<String>> {
    Ok(serde_json::from_str(json)?)
}

fn parse_dt(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}

fn status_to_str(status: HypothesisStatus) -> &'static str {
    match status {
        HypothesisStatus::Proposed => "PROPOSED",
        HypothesisStatus::Investigating => "INVESTIGATING",
        HypothesisStatus::Supported => "SUPPORTED",
        HypothesisStatus::Accepted => "ACCEPTED",
        HypothesisStatus::Contested => "CONTESTED",
        HypothesisStatus::Stale => "STALE",
        HypothesisStatus::Rejected => "REJECTED",
    }
}

fn status_from_str(s: &str) -> Result<HypothesisStatus> {
    Ok(match s {
        "PROPOSED" => HypothesisStatus::Proposed,
        "INVESTIGATING" => HypothesisStatus::Investigating,
        "SUPPORTED" => HypothesisStatus::Supported,
        "ACCEPTED" => HypothesisStatus::Accepted,
        "CONTESTED" => HypothesisStatus::Contested,
        "STALE" => HypothesisStatus::Stale,
        "REJECTED" => HypothesisStatus::Rejected,
        other => bail!("unknown hypothesis status in database: {other}"),
    })
}

fn kind_to_str(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::DependsOn => "DEPENDS_ON",
        DependencyKind::Supports => "SUPPORTS",
        DependencyKind::Contradicts => "CONTRADICTS",
        DependencyKind::Implies => "IMPLIES",
    }
}

fn kind_from_str(s: &str) -> Result<DependencyKind> {
    Ok(match s {
        "DEPENDS_ON" => DependencyKind::DependsOn,
        "SUPPORTS" => DependencyKind::Supports,
        "CONTRADICTS" => DependencyKind::Contradicts,
        "IMPLIES" => DependencyKind::Implies,
        other => bail!("unknown dependency kind in database: {other}"),
    })
}
