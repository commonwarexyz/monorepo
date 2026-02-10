use super::*;
use crate::{ingress, Actor};
use commonware_runtime::{deterministic, Runner, Spawner};
use commonware_utils::channel::fallible::OneshotExt;

struct AskReadWriteActor {
    value: u64,
}

ingress! {
    AskReadWriteMailbox,

    pub tell Seed { value: u64 };
    pub ask read_write BumpAndGet { delta: u64 } -> u64;
    pub ask Read -> u64;
}

impl<E: Spawner> Actor<E> for AskReadWriteActor {
    type Mailbox = AskReadWriteMailbox;
    type Ingress = AskReadWriteMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = ();
    type Snapshot = u64;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.value
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: AskReadWriteMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            AskReadWriteMailboxReadOnlyMessage::Read { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: AskReadWriteMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            AskReadWriteMailboxReadWriteMessage::Seed { value } => {
                self.value = value;
            }
            AskReadWriteMailboxReadWriteMessage::BumpAndGet { delta, response } => {
                self.value += delta;
                response.send_lossy(self.value);
            }
        }
        Ok(())
    }
}

#[test]
fn test_ask_read_write_routes_to_write_handler() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let actor = AskReadWriteActor { value: 0 };
        let (mailbox, service) =
            ServiceBuilder::new(actor).build(context.with_label("ask_read_write"));
        service.start();

        mailbox.seed(10).await.expect("seed failed");
        let bumped = mailbox.bump_and_get(5).await.expect("ask failed");
        assert_eq!(bumped, 15);

        let value = mailbox.read().await.expect("read failed");
        assert_eq!(value, 15);
    });
}
