#![cfg(target_arch = "wasm32")]

use commonware_runtime::{Clock, Error, Scheduler, web::Runtime};
use js_sys::Promise;
use std::{
    cell::RefCell,
    rc::Rc,
    time::{Duration, SystemTime},
};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test(async)]
async fn wall_clock_is_anchored_without_std_time_support() {
    let runtime = Runtime::new().unwrap();
    let current = runtime.spawn_root(|context| async move { context.current() });

    assert!(
        current
            .await
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            > Duration::from_secs(50 * 365 * 24 * 60 * 60)
    );
}

#[wasm_bindgen_test(async)]
async fn root_supervises_spawned_children() {
    let runtime = Runtime::new().unwrap();
    let root = runtime
        .spawn_root(|context| async move { context.spawn(|_| async { 7_u8 }).await.unwrap() });

    assert_eq!(root.await.unwrap(), 7);
}

#[wasm_bindgen_test(async)]
async fn spawns_browser_local_futures() {
    let runtime = Runtime::new().unwrap();
    let local = Rc::new(RefCell::new(0));
    let handle = runtime.spawn_root({
        let local = Rc::clone(&local);
        move |_| async move {
            JsFuture::from(Promise::resolve(&wasm_bindgen::JsValue::NULL))
                .await
                .unwrap();
            *local.borrow_mut() = 7;
            local
        }
    });

    let output = handle.await.unwrap();
    assert_eq!(*output.borrow(), 7);
}

#[wasm_bindgen_test(async)]
async fn shutdown_aborts_pending_roots() {
    let runtime = Runtime::new().unwrap();
    let handle = runtime
        .clone()
        .spawn_root(|_| futures::future::pending::<()>());
    runtime.shutdown(0);
    assert!(matches!(handle.await, Err(Error::Closed)));
}

#[wasm_bindgen_test(async)]
async fn clock_uses_monotonic_elapsed_time() {
    let runtime = Runtime::new().unwrap();
    let handle = runtime.spawn_root(|context| async move {
        let before = context.current();
        context.sleep(Duration::from_millis(1)).await;
        context.current().duration_since(before).unwrap()
    });
    assert!(handle.await.unwrap() >= Duration::from_millis(1));
}
