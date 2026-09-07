//! Tracks Ghidra mutations Debura has applied (PROJECT.md S30, M8) --
//! reversible by design: every row records what changed and from what, so
//! a mutation whose source hypothesis later gets REJECTED can be undone
//! instead of permanently poisoning the decompiler state.
//!
//! This is sync state with Ghidra, not an epistemic claim about the
//! program -- deliberately not part of `KnowledgeGraph`/`knowledge::save`,
//! and written immediately on each change rather than as a full snapshot.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use debura_knowledge::HypothesisId;
use rusqlite::{params, Connection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationKind {
    RenameFunction,
}

fn kind_to_str(kind: MutationKind) -> &'static str {
    match kind {
        MutationKind::RenameFunction => "RENAME_FUNCTION",
    }
}

fn kind_from_str(s: &str) -> Result<MutationKind> {
    Ok(match s {
        "RENAME_FUNCTION" => MutationKind::RenameFunction,
        other => bail!("unknown mutation kind in database: {other}"),
    })
}

#[derive(Debug, Clone)]
pub struct GhidraMutation {
    pub id: u64,
    pub hypothesis_id: HypothesisId,
    pub kind: MutationKind,
    pub target_address: String,
    pub previous_value: String,
    pub new_value: String,
    pub applied_at: DateTime<Utc>,
    pub reverted_at: Option<DateTime<Utc>>,
}

/// Records that a mutation was just applied. Call only after Ghidra
/// confirms it actually took effect.
pub fn record(
    conn: &Connection,
    hypothesis_id: HypothesisId,
    kind: MutationKind,
    target_address: &str,
    previous_value: &str,
    new_value: &str,
) -> Result<u64> {
    conn.execute(
        "INSERT INTO ghidra_mutations
            (hypothesis_id, kind, target_address, previous_value, new_value, applied_at, reverted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            hypothesis_id.0,
            kind_to_str(kind),
            target_address,
            previous_value,
            new_value,
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(conn.last_insert_rowid() as u64)
}

/// Every mutation that hasn't been reverted -- i.e., currently in effect.
pub fn list_unreverted(conn: &Connection) -> Result<Vec<GhidraMutation>> {
    let mut stmt = conn.prepare(
        "SELECT id, hypothesis_id, kind, target_address, previous_value, new_value, applied_at
         FROM ghidra_mutations
         WHERE reverted_at IS NULL",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    rows.into_iter()
        .map(
            |(id, hypothesis_id, kind, target_address, previous_value, new_value, applied_at)| {
                Ok(GhidraMutation {
                    id: id as u64,
                    hypothesis_id: HypothesisId(hypothesis_id as u64),
                    kind: kind_from_str(&kind)?,
                    target_address,
                    previous_value,
                    new_value,
                    applied_at: DateTime::parse_from_rfc3339(&applied_at)?.with_timezone(&Utc),
                    reverted_at: None,
                })
            },
        )
        .collect()
}

pub fn mark_reverted(conn: &Connection, id: u64, at: DateTime<Utc>) -> Result<()> {
    conn.execute(
        "UPDATE ghidra_mutations SET reverted_at = ?1 WHERE id = ?2",
        params![at.to_rfc3339(), id],
    )?;
    Ok(())
}
