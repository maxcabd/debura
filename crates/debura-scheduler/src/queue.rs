use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};

use debura_knowledge::KnowledgeGraph;

use crate::priority::priority;
use crate::task::Task;

struct Scored {
    priority: f64,
    task: Task,
}

impl PartialEq for Scored {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}
impl Eq for Scored {}
impl PartialOrd for Scored {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Scored {
    fn cmp(&self, other: &Self) -> Ordering {
        // Priorities are always finite (computed by `priority`, never
        // sourced from outside) -- total_cmp is just to give BinaryHeap a
        // real Ord without pulling in a crate for it.
        self.priority.total_cmp(&other.priority)
    }
}

/// The task queue (PROJECT.md S16, S27): a max-heap ordered by
/// expected-value, recomputed at enqueue time from the graph's current
/// state. PROJECT.md S15's example table (architectural importance vs.
/// cost) is the target; `priority` is today's much simpler approximation
/// of it.
#[derive(Default)]
pub struct Scheduler {
    queue: BinaryHeap<Scored>,
    /// Tasks currently sitting in `queue`, so a second identical task
    /// can't be queued alongside one that's already waiting. Without
    /// this, retry-after-rejection could double up: two hypotheses on
    /// the same subject rejected within the same commit batch both read
    /// the same not-yet-incremented persisted attempt count and both
    /// enqueue a retry, defeating the bounded-retry cap (PROJECT.md M10
    /// -- observed compounding a subject past 3 AnalyzeFunction attempts
    /// up to 10 in a real run before this was added).
    queued: HashSet<Task>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, graph: &KnowledgeGraph, task: Task) {
        if !self.queued.insert(task.clone()) {
            return;
        }
        let priority = priority(graph, &task);
        self.queue.push(Scored { priority, task });
    }

    pub fn pop(&mut self) -> Option<Task> {
        let task = self.queue.pop().map(|s| s.task)?;
        self.queued.remove(&task);
        Some(task)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}
