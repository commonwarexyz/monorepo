// Reduced transition surface for bounded exhaustive verification.
module bounded {
    import instance as model from "./instance"

    action init = model::init
    action step = model::bounded_step
    val lifecycle_invariants = model::lifecycle_invariants
}
