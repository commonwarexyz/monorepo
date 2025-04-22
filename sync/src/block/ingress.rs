/// Messages handled by the Synchronizer actor.
#[derive(Debug, Clone)] // Removed Encode/Decode for simplicity, handle via Mailbox
pub enum SyncMessage<I: Copy + Ord + Send + Sync + 'static> {
    /// Request the current synchronization status.
    GetStatus,
    /// Force an immediate check for new data.
    ForceCheck,
}

/// Response from the Synchronizer actor.
#[derive(Debug, Clone)] // Removed Encode/Decode
pub enum SyncResponse<I: Copy + Ord + Send + Sync + 'static> {
    /// Current synchronization status.
    Status {
        /// The highest index known to be successfully stored locally and contiguously.
        local_head: Option<I>,
        /// The highest index known/targeted by the synchronizer based on latest proof.
        target_head: Option<I>,
        /// Whether the synchronizer is currently actively fetching/processing.
        is_active: bool,
    },
    /// Acknowledgment of a command.
    Ack,
}
