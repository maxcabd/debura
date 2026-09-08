use anyhow::Result;
use rusqlite::Connection;

/// Ordered, append-only list of schema migrations.
///
/// Each entry runs at most once per database, tracked via `schema_migrations`.
/// M2/M3 add the observation/evidence/hypothesis/dependency tables here.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_init",
        r#"
        CREATE TABLE IF NOT EXISTS project_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        "#,
    ),
    (
        "0002_knowledge",
        r#"
        CREATE TABLE observations (
            id          INTEGER PRIMARY KEY,
            subject     TEXT NOT NULL,
            predicate   TEXT NOT NULL,
            value       TEXT NOT NULL,
            confidence  REAL NOT NULL,
            source      TEXT NOT NULL,
            artifact    TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE evidence (
            id                  INTEGER PRIMARY KEY,
            observation_id      INTEGER NOT NULL REFERENCES observations(id),
            relevance           TEXT NOT NULL,
            source              TEXT NOT NULL,
            location            TEXT,
            artifact_reference  TEXT
        );

        CREATE TABLE hypotheses (
            id                      INTEGER PRIMARY KEY,
            subject                 TEXT NOT NULL,
            predicate               TEXT NOT NULL,
            value                   TEXT NOT NULL,
            confidence              REAL NOT NULL,
            status                  TEXT NOT NULL,
            supporting_evidence     TEXT NOT NULL,
            contradicting_evidence  TEXT NOT NULL,
            created_by              INTEGER,
            created_at              TEXT NOT NULL,
            updated_at              TEXT NOT NULL,
            last_verified_at        TEXT
        );

        CREATE TABLE dependencies (
            source_hypothesis  INTEGER NOT NULL REFERENCES hypotheses(id),
            target_hypothesis  INTEGER NOT NULL REFERENCES hypotheses(id),
            kind               TEXT NOT NULL,
            PRIMARY KEY (source_hypothesis, target_hypothesis, kind)
        );
        "#,
    ),
    (
        "0003_investigations",
        r#"
        CREATE TABLE investigations (
            id                   INTEGER PRIMARY KEY,
            task                 TEXT NOT NULL,
            target               TEXT NOT NULL,
            context_snapshot     TEXT NOT NULL,
            tool_calls           TEXT NOT NULL,
            observations         TEXT NOT NULL,
            hypotheses_created   TEXT NOT NULL,
            hypotheses_modified  TEXT NOT NULL,
            evidence_created     TEXT NOT NULL,
            result               TEXT NOT NULL,
            followup_tasks       TEXT NOT NULL,
            created_at           TEXT NOT NULL
        );
        "#,
    ),
    (
        "0004_ghidra_mutations",
        r#"
        CREATE TABLE ghidra_mutations (
            id               INTEGER PRIMARY KEY,
            hypothesis_id    INTEGER NOT NULL,
            kind             TEXT NOT NULL,
            target_address   TEXT NOT NULL,
            previous_value   TEXT NOT NULL,
            new_value        TEXT NOT NULL,
            applied_at       TEXT NOT NULL,
            reverted_at      TEXT
        );
        "#,
    ),
    (
        "0005_rejection_reason",
        r#"
        ALTER TABLE hypotheses ADD COLUMN rejection_reason TEXT;
        "#,
    ),
    (
        "0006_observation_lifecycle",
        r#"
        ALTER TABLE observations ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';
        ALTER TABLE observations ADD COLUMN superseded_by INTEGER;
        "#,
    ),
];

pub fn run(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            name       TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    for (name, sql) in MIGRATIONS {
        let already_applied: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = ?1)",
            [name],
            |row| row.get(0),
        )?;

        if already_applied {
            continue;
        }

        conn.execute_batch(sql)?;
        conn.execute("INSERT INTO schema_migrations (name) VALUES (?1)", [name])?;
        tracing::debug!(migration = name, "applied migration");
    }

    Ok(())
}
