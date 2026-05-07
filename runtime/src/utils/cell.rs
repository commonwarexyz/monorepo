use std::ops::{Deref, DerefMut};

const MISSING_CONTEXT: &str = "runtime context missing";
const DUPLICATE_CONTEXT: &str = "runtime context already present";

/// Spawn a task using a [`Cell`] by taking its context, restoring the context synchronously
/// in the spawned closure, and returning the provided future directly to the runtime.
///
/// The macro uses the context's default spawn configuration (supervised, shared executor with
/// `blocking == false`). If you need to mark the task as blocking or request a dedicated thread,
/// take the context via [`Cell::take`] and call the appropriate [`crate::Spawner`] methods before spawning.
#[macro_export]
macro_rules! spawn_cell {
    ($cell:expr, $body:expr $(,)?) => {{
        let __commonware_context = $cell.take();
        $crate::Spawner::spawn(__commonware_context, move |context| {
            $cell.restore(context);
            $body
        })
    }};
}

/// A wrapper around context that allows it to be taken and returned without requiring
/// all interactions to unwrap (as with `Option<C>`).
#[derive(Debug)]
pub enum Cell<C> {
    /// A context available for use.
    Present(C),
    /// The context has been taken elsewhere.
    Missing,
}

impl<C> Cell<C> {
    /// Create a new slot containing `context`.
    pub const fn new(context: C) -> Self {
        Self::Present(context)
    }

    /// Remove the context from the slot, panicking if it is missing.
    pub fn take(&mut self) -> C {
        match std::mem::replace(self, Self::Missing) {
            Self::Present(context) => context,
            Self::Missing => panic!("{}", MISSING_CONTEXT),
        }
    }

    /// Return a context to the slot, panicking if one is already present.
    pub fn restore(&mut self, context: C) {
        match self {
            Self::Present(_) => panic!("{}", DUPLICATE_CONTEXT),
            Self::Missing => {
                *self = Self::Present(context);
            }
        }
    }

    /// Returns a reference to the context.
    ///
    /// # Panics
    ///
    /// Panics if the context is missing.
    pub fn as_present(&self) -> &C {
        match self {
            Self::Present(context) => context,
            Self::Missing => panic!("{}", MISSING_CONTEXT),
        }
    }

    /// Returns a mutable reference to the context.
    ///
    /// # Panics
    ///
    /// Panics if the context is missing.
    pub fn as_present_mut(&mut self) -> &mut C {
        match self {
            Self::Present(context) => context,
            Self::Missing => panic!("{}", MISSING_CONTEXT),
        }
    }

    /// Consume the slot, returning the context.
    ///
    /// # Panics
    ///
    /// Panics if the context is missing.
    pub fn into_present(self) -> C {
        match self {
            Self::Present(context) => context,
            Self::Missing => panic!("{}", MISSING_CONTEXT),
        }
    }
}

impl<C> Deref for Cell<C> {
    type Target = C;

    fn deref(&self) -> &C {
        self.as_present()
    }
}

impl<C> DerefMut for Cell<C> {
    fn deref_mut(&mut self) -> &mut C {
        self.as_present_mut()
    }
}

impl<C> AsRef<C> for Cell<C> {
    fn as_ref(&self) -> &C {
        self.as_present()
    }
}

impl<C> AsMut<C> for Cell<C> {
    fn as_mut(&mut self) -> &mut C {
        self.as_present_mut()
    }
}
