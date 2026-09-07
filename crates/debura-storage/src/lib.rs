pub mod knowledge;
mod migrations;

use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

/// Opens (creating if necessary) a project's SQLite database and brings its
/// schema up to date. This is `project.sqlite`: Debura's durable memory.
pub fn init_project_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    migrations::run(&conn)?;
    Ok(conn)
}
