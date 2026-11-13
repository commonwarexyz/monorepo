//! Tests of runtime threads on every runner.

use crate::{
    Clock, Error, Metrics, Runner, Spawner, Supervisor, ThreadError, deterministic, reschedule,
    tokio,
};
#[cfg(target_os = "linux")]
use crate::iouring;
use futures::future::pending;
use rstest::rstest;
use std::{cell::RefCell, rc::Rc, time::Duration};

#[rstest]
#[case::deterministic(deterministic::Runner::default())]
#[case::tokio(tokio::Runner::default())]
#[cfg_attr(target_os = "linux", case::iouring(iouring::Runner::default()))]
fn test_thread_smoke<R: Runner>(#[case] runner: R)
where
    R::Context: Spawner + Clock + Metrics,
{
    runner.start(|context| async move {
        // A root task with !Send state shared by its residents.
        let value = context
            .child("root")
            .thread()
            .spawn(|local| async move {
                let shared = Rc::new(RefCell::new(0));
                let mut handles = Vec::new();
                for _ in 0..10 {
                    let shared = shared.clone();
                    handles.push(local.child("leaf").spawn_local(move |_| async move {
                        reschedule().await;
                        *shared.borrow_mut() += 1;
                        Rc::new(7)
                    }));
                }
                let mut total = 0;
                for handle in handles {
                    total += *handle.await.unwrap();
                }
                let count = *shared.borrow();
                total + count
            })
            .unwrap()
            .await
            .unwrap();
        assert_eq!(value, 80);

        // A built thread hosting placed spawns and spawn_on tasks.
        let thread = context.child("built").thread().build().unwrap();
        let placed = context.child("placed").on(&thread);
        let a = placed.spawn(|_| async { 1 });
        let b = context
            .child("remote")
            .spawn_on(&thread, |local| async move {
                let inner = local.child("inner").spawn_local(|_| async { Rc::new(2) });
                *inner.await.unwrap()
            });
        assert_eq!(a.await.unwrap() + b.await.unwrap(), 3);

        // An attached context.
        let attached = context.child("attached").thread().attach().unwrap();
        let c = attached.child("x").spawn(|ctx| async move {
            ctx.sleep(Duration::from_millis(1)).await;
            3
        });
        assert_eq!(c.await.unwrap(), 3);

        // Closing a thread aborts its residents.
        let lineage = context.child("lineage");
        let (tx, rx) = futures::channel::oneshot::channel();
        let owner = lineage.spawn(move |ctx| async move {
            let thread = ctx.child("t").thread().build().unwrap();
            let probe = ctx.child("probe").spawn_on(&thread, |_| pending::<()>());
            tx.send((thread, probe)).ok().unwrap();
            pending::<()>().await;
        });
        let (thread, probe) = rx.await.unwrap();
        owner.abort();
        assert!(matches!(probe.await, Err(Error::Closed)));
        let late = context.child("late").spawn_on(&thread, |_| async {});
        assert!(matches!(late.await, Err(Error::Closed)));

        // Pins validate.
        let empty: Vec<usize> = Vec::new();
        assert!(matches!(
            context.child("empty").thread().pin(empty).build(),
            Err(ThreadError::EmptyCpus)
        ));
    });
}
