use commonware_utils::union;

pub const ACK_SUFFIX: &[u8] = b"_ACK";
pub const CAR_SUFFIX: &[u8] = b"_CAR";

pub fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

pub fn car_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CAR_SUFFIX)
}
