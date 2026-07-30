//! Tests for cancelable benchmark producer coordination.

#[test]
fn start_releases_every_ready_producer() {
    // Setup: Start two producers and wait until both reach the shared gate.
    let gate = std::sync::Arc::new(super::ProducerGate::new());
    let producers = (0..2)
        .map(|_| {
            let gate = std::sync::Arc::clone(&gate);
            std::thread::spawn(move || gate.arrive_and_wait())
        })
        .collect::<Vec<_>>();
    assert!(gate.wait_until_ready(2));

    // Action: Release the complete producer set into measured work.
    gate.start();
    let releases = producers
        .into_iter()
        .map(|producer| producer.join().unwrap())
        .collect::<Vec<_>>();

    // Assertion: Every waiting producer observes the start decision.
    assert_eq!(releases, [super::ProducerRelease::Start; 2]);
}

#[test]
fn cancel_releases_a_partial_producer_set() {
    // Setup: Let one producer arrive while the coordinator expects another.
    let gate = std::sync::Arc::new(super::ProducerGate::new());
    let producer_gate = std::sync::Arc::clone(&gate);
    let producer = std::thread::spawn(move || producer_gate.arrive_and_wait());
    assert!(gate.wait_until_ready(1));

    // Action: Cancel setup as a failed second spawn would.
    gate.cancel();
    let all_ready = gate.wait_until_ready(2);
    let release = producer.join().unwrap();

    // Assertion: The coordinator detects the partial set and the producer exits.
    assert!(!all_ready);
    assert_eq!(release, super::ProducerRelease::Cancel);
}

#[test]
fn producer_panic_cancels_before_arrival() {
    // Setup: Give one producer work that panics before it reaches the gate.
    let gate = std::sync::Arc::new(super::ProducerGate::new());
    let producer_gate = std::sync::Arc::clone(&gate);
    let producer = std::thread::spawn(move || {
        producer_gate.cancel_on_unwind(|| panic!("injected producer setup panic"));
    });

    // Action: Join the producer and wait for an arrival that cannot occur.
    let panicked = producer.join();
    let all_ready = gate.wait_until_ready(1);

    // Assertion: The panic is preserved and cancellation prevents a coordinator hang.
    assert!(panicked.is_err());
    assert!(!all_ready);
}

#[test]
fn cancellation_dominates_start() {
    // Setup: Release the gate as though measured cancellation had begun.
    let gate = super::ProducerGate::new();
    gate.start();

    // Action: Publish a later producer failure, then try to start again.
    gate.cancel();
    gate.start();
    let release = gate.arrive_and_wait();

    // Assertion: Neither the prior nor repeated start hides cancellation.
    assert_eq!(release, super::ProducerRelease::Cancel);
}
