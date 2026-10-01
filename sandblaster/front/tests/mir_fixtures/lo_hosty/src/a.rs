
pub struct Q(u64);

impl Q {
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl codec::Write for Q {
    fn write(&self, buf: &mut Vec<u8>) {
        buf.push(self.0 as u8);
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod full;
    }
}
