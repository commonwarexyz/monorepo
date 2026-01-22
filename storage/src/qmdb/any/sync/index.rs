use crate::translator::Translator;
use commonware_runtime::Metrics;

/// An index used by a [crate::qmdb::any::db::Db].
pub trait Index: Sized {
    type Translator: crate::translator::Translator + Clone;
    fn new(ctx: impl Metrics, translator: Self::Translator) -> Self;
}

impl<T: Translator, V: Eq + Send + Sync> crate::qmdb::any::sync::Index
    for crate::index::unordered::Index<T, V>
{
    type Translator = T;
    fn new(ctx: impl Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Eq + Send + Sync> crate::qmdb::any::sync::Index
    for crate::index::ordered::Index<T, V>
{
    type Translator = T;
    fn new(ctx: impl Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}
