#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::sync::{TracedAsyncMutex, TracedAsyncRwLock, UpgradableAsyncRwLock};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    MutexAdd(u64),
    RwRead,
    RwWrite(u64),
    UpgRead,
    UpgWrite(u64),
    UpgReadThenUpgrade(u64),
    UpgWriteThenDowngrade(u64),
}

/// `first` guarantees the op list is never empty.
#[derive(Arbitrary, Debug)]
struct Plan {
    mutex_init: u64,
    rw_init: u64,
    upg_init: u64,
    first: Op,
    rest: Vec<Op>,
}

fn fuzz(plan: Plan) {
    block_on(async move {
        let mutex = TracedAsyncMutex::new("fuzz", plan.mutex_init);
        let rw = TracedAsyncRwLock::new("fuzz", plan.rw_init);
        let upg = UpgradableAsyncRwLock::new(plan.upg_init);

        // Shadow values: a guard must always observe the last value written through it.
        let mut mutex_shadow = plan.mutex_init;
        let mut rw_shadow = plan.rw_init;
        let mut upg_shadow = plan.upg_init;

        for op in core::iter::once(plan.first).chain(plan.rest) {
            match op {
                Op::MutexAdd(v) => {
                    let mut guard = mutex.lock().await;
                    *guard = guard.wrapping_add(v);
                    mutex_shadow = mutex_shadow.wrapping_add(v);
                    assert_eq!(*guard, mutex_shadow);
                }
                Op::RwRead => {
                    assert_eq!(*rw.read().await, rw_shadow);
                }
                Op::RwWrite(v) => {
                    let mut guard = rw.write().await;
                    *guard = v;
                    rw_shadow = v;
                    assert_eq!(*guard, rw_shadow);
                }
                Op::UpgRead => {
                    assert_eq!(*upg.read().await, upg_shadow);
                }
                Op::UpgWrite(v) => {
                    let mut guard = upg.write().await;
                    *guard = v;
                    upg_shadow = v;
                    assert_eq!(*guard, upg_shadow);
                }
                Op::UpgReadThenUpgrade(v) => {
                    let guard = upg.upgradable_read().await;
                    assert_eq!(*guard, upg_shadow);
                    let mut writer = guard.upgrade().await;
                    *writer = v;
                    upg_shadow = v;
                    assert_eq!(*writer, upg_shadow);
                }
                Op::UpgWriteThenDowngrade(v) => {
                    let mut writer = upg.write().await;
                    *writer = v;
                    upg_shadow = v;
                    let reader = writer.downgrade_to_upgradable();
                    assert_eq!(*reader, upg_shadow);
                }
            }
        }

        assert_eq!(upg.into_inner(), upg_shadow);
    });
}

fuzz_target!(|plan: Plan| {
    fuzz(plan);
});
