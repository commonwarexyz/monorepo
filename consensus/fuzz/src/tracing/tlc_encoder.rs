//! Encodes a canonical simplex consensus [`Trace`] into a JSON action
//! sequence for the controlled TLC server.
//!
//! Takes the canonical event list and renders the action list accepted by
//! the Java `SimplexActionMapper`. The semantic walk lives in
//! [`super::encoder::lower_events_to_actions`] so the Quint and TLC
//! back-ends always agree on the action sequence; this module only
//! renders the resulting [`super::encoder::ActionItem`]s as JSON.
//!
//! See `tlc-controlled/src/tlc2/controlled/protocol/SimplexActionMapper.java`
//! for the per-action JSON schema accepted by the server.

use super::encoder::{
    build_block_map_from_events, lower_events_to_actions, ActionItem, CertItem,
};
use commonware_consensus::simplex::replay::Trace;
use serde_json::{json, Value};

/// Canonical entry point: encode a [`Trace`] as a JSON action sequence
/// for the controlled TLC server. The lowering from canonical events
/// to [`ActionItem`] is 1:1, so this is just a rendering pass.
pub fn encode_from_trace(trace: &Trace) -> Vec<Value> {
    let block_map = build_block_map_from_events(&trace.events);
    let items = lower_events_to_actions(&trace.events, &block_map, trace.topology.faults);
    let mut out = Vec::with_capacity(items.len());
    for item in &items {
        out.push(render_item(item));
    }
    out
}

/// Renders a single semantic action item as a `{name, params}` JSON object
/// matching the shapes documented on `SimplexActionMapper.java`.
fn render_item(item: &ActionItem) -> Value {
    match item {
        ActionItem::Propose {
            leader,
            payload,
            parent_view,
            ..
        } => json!({
            "name": "propose",
            "params": {
                "id": leader,
                "payload": payload,
                "parent": parent_view,
            },
        }),
        ActionItem::SendNotarizeVote {
            view,
            parent_view,
            payload,
            sig,
        } => json!({
            "name": "send_notarize_vote",
            "params": {
                "view": view,
                "parent": parent_view,
                "payload": payload,
                "sig": sig,
            },
        }),
        ActionItem::SendNullifyVote { view, sig } => json!({
            "name": "send_nullify_vote",
            "params": {
                "view": view,
                "sig": sig,
            },
        }),
        ActionItem::SendFinalizeVote {
            view,
            parent_view,
            payload,
            sig,
        } => json!({
            "name": "send_finalize_vote",
            "params": {
                "view": view,
                "parent": parent_view,
                "payload": payload,
                "sig": sig,
            },
        }),
        ActionItem::SendCertificate { cert } => json!({
            "name": "send_certificate",
            "params": cert_params(cert, None),
        }),
        ActionItem::OnNotarize {
            receiver,
            view,
            parent_view,
            payload,
            sig,
        } => json!({
            "name": "on_notarize",
            "params": {
                "id": receiver,
                "view": view,
                "parent": parent_view,
                "payload": payload,
                "sig": sig,
            },
        }),
        ActionItem::OnNullify {
            receiver,
            view,
            sig,
        } => json!({
            "name": "on_nullify",
            "params": {
                "id": receiver,
                "view": view,
                "sig": sig,
            },
        }),
        ActionItem::OnFinalize {
            receiver,
            view,
            parent_view,
            payload,
            sig,
        } => json!({
            "name": "on_finalize",
            "params": {
                "id": receiver,
                "view": view,
                "parent": parent_view,
                "payload": payload,
                "sig": sig,
            },
        }),
        ActionItem::OnCertificate { receiver, cert } => json!({
            "name": "on_certificate",
            "params": cert_params(cert, Some(receiver)),
        }),
    }
}

/// Builds the JSON params object for a `send_certificate` /
/// `on_certificate` action. Notarization and finalization carry the full
/// proposal record; nullification carries only `view`. When `id` is
/// provided (the `on_certificate` case) it is added to the params.
fn cert_params(cert: &CertItem, id: Option<&str>) -> Value {
    let mut params = match cert {
        CertItem::Notarization {
            view,
            parent_view,
            payload,
            signers,
            ghost_sender,
        } => json!({
            "type": "notarization",
            "proposal": {
                "view": view,
                "parent": parent_view,
                "payload": payload,
            },
            "signatures": signers,
            "ghost_sender": ghost_sender,
        }),
        CertItem::Nullification {
            view,
            signers,
            ghost_sender,
        } => json!({
            "type": "nullification",
            "view": view,
            "signatures": signers,
            "ghost_sender": ghost_sender,
        }),
        CertItem::Finalization {
            view,
            parent_view,
            payload,
            signers,
            ghost_sender,
        } => json!({
            "type": "finalization",
            "proposal": {
                "view": view,
                "parent": parent_view,
                "payload": payload,
            },
            "signatures": signers,
            "ghost_sender": ghost_sender,
        }),
    };
    if let (Some(id), Value::Object(map)) = (id, &mut params) {
        map.insert("id".to_string(), Value::String(id.to_string()));
    }
    params
}
