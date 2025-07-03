enum Message {}

pub struct Mailbox<M: Idable> {}

impl Collector for Mailbox {
    type Message = E::Message;
    type PublicKey = E::Message::PublicKey;

    fn send(
        &mut self,
        message: Self::Message,
        transformer: fn(Self::Message, Self::PublicKey) -> Bytes,
    ) -> impl Future<Output = ()> + Send {
        todo!()
    }

    fn peek(
        &mut self,
        id: <Self::Message as Idable>::ID,
    ) -> impl Future<Output = oneshot::Receiver<HashMap<Self::PublicKey, Bytes>>> + Send {
        todo!()
    }

    fn cancel(&mut self, id: <Self::Message as Idable>::ID) -> impl Future<Output = ()> + Send {
        todo!()
    }
}
