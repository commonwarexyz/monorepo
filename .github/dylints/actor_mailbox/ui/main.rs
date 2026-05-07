#![allow(dead_code)]

mod tokio {
    pub mod sync {
        pub mod mpsc {
            pub struct Sender<T>(core::marker::PhantomData<T>);
            pub struct Receiver<T>(core::marker::PhantomData<T>);
            pub struct UnboundedSender<T>(core::marker::PhantomData<T>);
            pub struct UnboundedReceiver<T>(core::marker::PhantomData<T>);

            pub fn channel<T>(_: usize) -> (Sender<T>, Receiver<T>) {
                (
                    Sender(core::marker::PhantomData),
                    Receiver(core::marker::PhantomData),
                )
            }

            pub fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
                (
                    UnboundedSender(core::marker::PhantomData),
                    UnboundedReceiver(core::marker::PhantomData),
                )
            }
        }
    }
}

mod system {
    pub mod actors {
        pub mod router {
            use crate::tokio::sync::mpsc;

            struct Bad {
                sender: mpsc::Sender<u8>,
                receiver: mpsc::Receiver<u8>,
            }

            fn bad() {
                let _ = mpsc::channel::<u8>(1);
                let _ = mpsc::unbounded_channel::<u8>();
            }
        }
    }

    pub mod relay {
        use crate::tokio::sync::mpsc::UnboundedSender;

        struct Bad {
            sender: UnboundedSender<u8>,
        }
    }

    pub mod ingress {
        use crate::tokio::sync::mpsc;

        struct Bad {
            sender: mpsc::UnboundedSender<u8>,
            receiver: mpsc::UnboundedReceiver<u8>,
        }
    }
}

mod outside_actor {
    use crate::tokio::sync::mpsc;

    struct Allowed {
        sender: mpsc::Sender<u8>,
    }

    fn allowed() {
        let _ = mpsc::channel::<u8>(1);
    }
}

fn main() {}
