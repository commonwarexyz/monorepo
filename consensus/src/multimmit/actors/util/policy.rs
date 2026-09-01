//! A mailbox policy that retains every overflowing message in arrival order.

/// Implements [`commonware_actor::mailbox::Policy`] for `$message` by retaining overflow in a
/// `VecDeque` in arrival order.
///
/// Use it only for messages whose producers bound their own backlog.
macro_rules! reliable_policy {
    (impl$(<$($generic:ident $(: $bound:path)?),+>)? for $message:ty) => {
        impl$(<$($generic $(: $bound)?),+>)? commonware_actor::mailbox::Policy for $message {
            type Overflow = std::collections::VecDeque<Self>;

            fn handle(overflow: &mut Self::Overflow, message: Self) {
                overflow.push_back(message);
            }
        }
    };
}
pub(crate) use reliable_policy;

#[cfg(test)]
mod tests {
    use commonware_actor::mailbox::Policy;
    use std::collections::VecDeque;

    struct Message(u8);

    reliable_policy!(impl for Message);

    struct Generic<T>(T);

    reliable_policy!(impl<T: Clone> for Generic<T>);

    #[test]
    fn overflow_is_retained_in_arrival_order() {
        let mut overflow = VecDeque::new();
        for value in 0..3 {
            <Message as Policy>::handle(&mut overflow, Message(value));
        }
        let values: Vec<u8> = overflow.into_iter().map(|Message(value)| value).collect();
        assert_eq!(values, vec![0, 1, 2]);

        let mut overflow = VecDeque::new();
        <Generic<u8> as Policy>::handle(&mut overflow, Generic(4));
        assert!(matches!(overflow.pop_front(), Some(Generic(4))));
    }
}
