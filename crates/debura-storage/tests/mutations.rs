use debura_knowledge::HypothesisId;
use debura_storage::mutations::{list_unreverted, mark_reverted, record, MutationKind};
use chrono::Utc;

#[test]
fn recorded_mutation_appears_unreverted_until_marked() {
    let dir = tempfile::tempdir().unwrap();
    let conn = debura_storage::init_project_db(&dir.path().join("project.sqlite")).unwrap();

    let hypothesis = HypothesisId(1);
    let id = record(
        &conn,
        hypothesis,
        MutationKind::RenameFunction,
        "0x1400016e4",
        "FUN_1400016e4",
        "TakeDamage",
    )
    .unwrap();

    let active = list_unreverted(&conn).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, id);
    assert_eq!(active[0].hypothesis_id, hypothesis);
    assert_eq!(active[0].previous_value, "FUN_1400016e4");
    assert_eq!(active[0].new_value, "TakeDamage");

    mark_reverted(&conn, id, Utc::now()).unwrap();

    assert!(list_unreverted(&conn).unwrap().is_empty());
}

/// Survives a restart the same way the knowledge graph does (M3's
/// requirement) -- two separate connections, never both open at once.
#[test]
fn mutation_log_survives_terminate_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("project.sqlite");

    {
        let conn = debura_storage::init_project_db(&db_path).unwrap();
        record(
            &conn,
            HypothesisId(1),
            MutationKind::RenameFunction,
            "0x1",
            "FUN_1",
            "compute",
        )
        .unwrap();
    }

    let conn = debura_storage::init_project_db(&db_path).unwrap();
    let active = list_unreverted(&conn).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].new_value, "compute");
}
