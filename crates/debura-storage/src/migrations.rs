use anyhow::Result;
use rusqlite::Connection;

/// Ordered, append-only list of schema migrations.
///
/// Each entry runs at most once per database, tracked via `schema_migrations`.
/// M2/M3 add the observation/evidence/hypothesis/dependency tables here.
const MIGRATIONS: &[(&str, &str)] = &[(
    "0001_init",
    r#"
    CREATE TABLE IF NOT EXISTS project_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    "#,
)];

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
