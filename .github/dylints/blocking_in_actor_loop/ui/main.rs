// edition:2021
#![allow(dead_code)]
#![warn(blocking_in_actor_loop)]

struct Context;

macro_rules! select_loop {
    ($context:expr, $body:block) => {{
        let _ = $context;
        loop {
            $body
            break;
        }
    }};
}

trait Handler {
    async fn process(&mut self);
}

trait Monitor {
    async fn collected(&mut self);
}

struct Mailbox;

impl Mailbox {
    async fn dial(&self) {}
}

struct Storage;

impl Storage {
    async fn put(&mut self) {}
}

struct ActorReceiver;

impl ActorReceiver {
    async fn recv(&mut self) -> Option<()> {
        None
    }
}

struct Stream;

impl Stream {
    async fn send(&mut self) {}

    async fn recv(&mut self) {}
}

async fn bad_handler(mut handler: impl Handler) {
    let context = Context;
    select_loop!(context, {
        handler.process().await;
    });
}

async fn bad_monitor(mut monitor: impl Monitor) {
    let context = Context;
    select_loop!(context, {
        monitor.collected().await;
    });
}

async fn bad_mailbox(mailbox: Mailbox) {
    let context = Context;
    select_loop!(context, {
        mailbox.dial().await;
    });
}

async fn storage_write_is_allowed(mut storage: Storage) {
    let context = Context;
    select_loop!(context, {
        storage.put().await;
    });
}

async fn bad_while_mailbox(mut mailbox: ActorReceiver, mut stream: Stream) {
    while let Some(()) = mailbox.recv().await {
        stream.send().await;
        stream.recv().await;
    }
}

fn main() {}
