//! Proves PROJECT.md M3's required property: run -> discover knowledge ->
//! terminate -> restart -> restore exact epistemic state. Uses a real file
//! on disk and two separate connections (never both open at once) so this
//! actually exercises "the process exited and came back", not just
//! "the same Connection can read what it wrote".

use debura_knowledge::{DependencyKind, HypothesisStatus, KnowledgeGraph};

#[test]
fn knowledge_graph_survives_terminate_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("project.sqlite");

    let (h1, h2, obs, evidence) = {
        let conn = debura_storage::init_project_db(&db_path).unwrap();

        let mut graph = KnowledgeGraph::new();

        let obs = graph.add_observation(
            "PlayerCharacter+0x138",
            "referenced_by",
            "HUD element labeled Health",
            0.95,
            "static_analysis",
            None,
        );
        let evidence = graph
            .add_evidence(obs, "displayed as Health in the HUD", "AnalyzeField", None, None)
            .unwrap();

        let h1 = graph.propose_hypothesis("PlayerCharacter+0x138", "semantic_role", "health", 0.91, None);
        graph.set_status(h1, HypothesisStatus::Accepted).unwrap();
        graph.attach_supporting_evidence(h1, evidence).unwrap();

        let h2 = graph.propose_hypothesis("F193", "semantic_role", "TakeDamage", 0.82, None);
        graph.set_status(h2, HypothesisStatus::Accepted).unwrap();
        graph
            .add_dependency(h2, h1, DependencyKind::DependsOn)
            .unwrap();

        // Reject h1 -- h2 should cascade to STALE, and that must survive
        // the round trip too, not just the direct field values.
        graph.set_status(h1, HypothesisStatus::Rejected).unwrap();

        debura_storage::knowledge::save(&conn, &graph).unwrap();

        (h1, h2, obs, evidence)
        // `conn` is dropped here -- the process's only handle on the
        // database goes away, same as it would on exit.
    };

    // "Restart": open a brand new connection to the same file.
    let conn = debura_storage::init_project_db(&db_path).unwrap();
    let restored = debura_storage::knowledge::load(&conn).unwrap();

    assert_eq!(restored.observations().count(), 1);
    assert_eq!(restored.all_evidence().count(), 1);
    assert_eq!(restored.hypotheses().count(), 2);
    assert_eq!(restored.dependencies().len(), 1);

    let restored_obs = restored.observation(obs).unwrap();
    assert_eq!(restored_obs.value, "HUD element labeled Health");

    let restored_h1 = restored.hypothesis(h1).unwrap();
    assert_eq!(restored_h1.status, HypothesisStatus::Rejected);
    assert_eq!(restored_h1.supporting_evidence, vec![evidence]);

    let restored_h2 = restored.hypothesis(h2).unwrap();
    assert_eq!(restored_h2.status, HypothesisStatus::Stale);
    assert_eq!(restored_h2.dependencies, vec![h1]);
}
