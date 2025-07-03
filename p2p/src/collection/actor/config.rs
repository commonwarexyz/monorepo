pub struct Config<O: Originator, E: Endpoint> {
    originator: O,
    endpoint: E,
    mailbox_size: usize,
}
