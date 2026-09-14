use super::{Kernel, WithKernel, portable::Portable, with_kernel};

struct TestPartialLoadStore;

impl WithKernel for TestPartialLoadStore {
    type Output = usize;

    fn call<K: Kernel>(self, kernel: K) -> usize {
        for len in (K::PARTIAL_GRANULARITY..=K::LANES).step_by(K::PARTIAL_GRANULARITY) {
            for offset in 0..8 {
                let mut input = vec![0xcc; offset + len + 8];
                for (i, byte) in input[offset..offset + len].iter_mut().enumerate() {
                    *byte = i as u8 + 1;
                }

                let value = kernel.load_partial(&input[offset..offset + len]);
                let mut loaded = vec![0xff; K::LANES];
                kernel.store(value, &mut loaded);
                assert_eq!(&loaded[..len], &input[offset..offset + len]);
                assert!(loaded[len..].iter().all(|&byte| byte == 0));

                let mut output = vec![0xa5; offset + len + 8];
                kernel.store_partial(value, &mut output[offset..offset + len]);
                assert!(output[..offset].iter().all(|&byte| byte == 0xa5));
                assert_eq!(&output[offset..offset + len], &input[offset..offset + len]);
                assert!(output[offset + len..].iter().all(|&byte| byte == 0xa5));
            }
        }
        K::LANES
    }
}

#[test]
fn partial_load_store() {
    assert_eq!(TestPartialLoadStore.call(Portable), Portable::LANES);
    let lanes = with_kernel(TestPartialLoadStore);
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx512f",
        target_feature = "gfni"
    ))]
    assert_eq!(lanes, 64);
    let _ = lanes;
}
