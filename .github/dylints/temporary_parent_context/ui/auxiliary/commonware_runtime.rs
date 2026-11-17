// Stands in for the real crate: the lint only fires on `Supervisor::child` and
// `Spawner::spawn` from a crate named `commonware_runtime`, so the UI test needs one.

pub trait Supervisor: Sized {
    fn child(&self, name: &'static str) -> Self;
    fn with_attribute(self, key: &'static str, value: &'static str) -> Self;
}

pub trait Spawner: Sized {
    fn shared(self, blocking: bool) -> Self;
    fn dedicated(self) -> Self;
    fn spawn(self, f: impl FnOnce()) -> std::future::Ready<()>;
}
