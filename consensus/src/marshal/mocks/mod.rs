pub mod application;
pub mod block;
pub mod harness;
pub mod resolver;
pub mod store;
#[cfg(test)]
pub mod strategy;
pub mod verifying;

#[cfg(test)]
pub(crate) fn assert_execution(metrics: &str, task: &str, execution: &str) {
    let name = format!("name=\"{task}\"");
    let mut lines = metrics
        .lines()
        .filter(|line| line.starts_with("runtime_tasks_spawned_total{") && line.contains(&name))
        .peekable();
    assert!(lines.peek().is_some(), "missing {name}: {metrics}");
    assert!(
        lines.all(|line| line.contains(&format!("execution=\"{execution}\""))),
        "{name} must use {execution}: {metrics}"
    );
}
