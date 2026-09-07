use std::cmp::Ordering;
use std::collections::BinaryHeap;

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
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, graph: &KnowledgeGraph, task: Task) {
        let priority = priority(graph, &task);
        self.queue.push(Scored { priority, task });
    }

    pub fn pop(&mut self) -> Option<Task> {
        self.queue.pop().map(|s| s.task)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}
