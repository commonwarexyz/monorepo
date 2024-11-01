use super::Translator;

fn cap<const N: usize>(key: &[u8]) -> [u8; N] {
    let mut capped = [0; N];
    let len = key.len().min(N);
    capped.copy_from_slice(&key[..len]);
    capped
}

#[derive(Clone)]
pub struct FourCap;

impl Translator for FourCap {
    type Key = [u8; 4];

    fn transform(&self, key: &[u8]) -> Self::Key {
        cap(key)
    }
}

#[derive(Clone)]
pub struct EightCap;

impl Translator for EightCap {
    type Key = [u8; 8];

    fn transform(&self, key: &[u8]) -> Self::Key {
        cap(key)
    }
}
