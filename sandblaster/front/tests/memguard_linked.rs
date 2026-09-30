//! The process-wide allocation cap (sandblaster-memguard) is installed in every
//! binary that links the front end.
#[test]
fn memguard_is_the_global_allocator() {
    let before = sandblaster_front::memguard::allocated();
    let v: Vec<u8> = std::hint::black_box(vec![1; 4 << 20]);
    let after = sandblaster_front::memguard::allocated();
    eprintln!("before={before} after={after} peak={}", sandblaster_front::memguard::peak());
    assert!(after >= before + (4 << 20), "the counting allocator is not installed");
    drop(v);
}
