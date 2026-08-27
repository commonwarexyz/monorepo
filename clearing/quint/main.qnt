// Executable Bajillion finite model.
module main {
    import instance.* from "./instance"

    val three_pending = chain_state.pipeline.length() == 3
}
