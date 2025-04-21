use std::{any::Any, cell::RefCell};

thread_local! {
    static CONTEXT: RefCell<Option<Box<dyn Any + Send>>> = RefCell::new(None);
}

/// Set the context value
pub(crate) fn set<C: Send + 'static>(context: C) {
    CONTEXT.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(context));
    });
}

/// Get the context value
pub fn get<C: Send + 'static>() -> C {
    CONTEXT.with(|cell| {
        // Attempt to take the context from the thread-local storage
        let mut borrow = cell.borrow_mut();
        match borrow.take() {
            Some(context) => {
                // Convert the context back to the original type
                let context = context.downcast::<C>().expect("failed to downcast context");
                *context
            }
            None => panic!("no context set"),
        }
    })
}

/// Clear the context value
pub(crate) fn clear() {
    CONTEXT.with(|cell| {
        *cell.borrow_mut() = None;
    });
}
