#![cfg(target_arch = "wasm32")]

use commonware_runtime::{Clock, Error, web::Runtime};
use js_sys::Promise;
use std::{cell::RefCell, rc::Rc, time::Duration};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

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
