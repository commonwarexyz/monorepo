pub trait Supervisor: Sized {
    fn child(&self, name: &'static str) -> Self;
    fn with_attribute(self, key: &'static str, value: &'static str) -> Self;
}

pub trait Spawner: Sized {
    fn spawn(self, f: impl FnOnce()) -> std::future::Ready<()>;
}
