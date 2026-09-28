#!/usr/bin/env python3
"""Validate diagnostic JSONL captures and export their event timelines."""

import argparse
import collections
import csv
import gzip
import json
import re
from pathlib import Path


def scalar(value):
    """Read scalar values from the capture's Debug field strings."""
    if not isinstance(value, str):
        return value
    if value.startswith("Some(") and value.endswith(")"):
        return scalar(value[5:-1])
    if value == "None":
        return None
    if value in {"true", "false"}:
        return value == "true"
    if re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    if value.startswith('"'):
        return json.loads(value)
    return value


def identity(fields):
    if not all(key in fields for key in ("chain", "height", "digest")):
        return None
    return int(fields["chain"]), int(fields["height"]), fields["digest"]


def block_rows(summary, captures):
    """Join exact block identities, retaining every node and incomplete outcome."""
    starts = {}
    parents = {}
    decoded = []
    for header, events, _ in captures:
        local = []
        for event in events:
            fields = {key: scalar(value) for key, value in event["fields"].items()}
            block = identity(fields)
            local.append((event, fields, block))
            if block and "parent" in fields:
                parents[block] = fields["parent"]
            if event["kind"] == "block_constructed" and block:
                submitted = fields.get("submission_unix_ns") or fields.get("construction_unix_ns")
                if submitted is not None and summary["common_cohort_start_unix_ns"] <= submitted < summary["common_cohort_end_unix_ns"]:
                    starts.setdefault(block, (header["node"], submitted))
        decoded.append((header, sorted(local, key=lambda row: row[0]["elapsed_ns"])))
    keys = ["receipt_ns", "eligible_ns", "signed_ns", "send_ns", "finality_ns", "placement_ns", "delivery_ns"]
    result = []
    for header, events in decoded:
        rows = {block: dict(node=header["node"], producer_node=start[0], chain=block[0], height=block[1], digest=block[2], submission_unix_ns=start[1], **dict.fromkeys(keys)) for block, start in starts.items()}
        bodies = collections.defaultdict(list)
        votes = {}
        frames = {}
        for event, fields, block in events:
            if event["kind"] == "endorsement_built" and block:
                bodies[fields["body"]].append((block, fields))
            if event["kind"] == "vote_body" and fields.get("event") == "artifact_signed":
                votes[fields["artifact"]] = fields["body"]
            if event["kind"] == "artifact_framed":
                frames[fields["frame_digest"]] = fields["artifact"]
        for event, fields, block in events:
            kind, elapsed = event["kind"], event["elapsed_ns"]
            column = {"block_received": "receipt_ns", "block_eligible": "eligible_ns", "order_planned": "placement_ns", "marshal_delivered": "delivery_ns"}.get(kind)
            if column and block in rows and rows[block][column] is None:
                rows[block][column] = fields.get("received_elapsed_ns", elapsed) if kind == "block_received" else elapsed
                if kind == "order_planned":
                    rows[block]["output_index"] = fields.get("index")
            if kind == "vote_body" and fields.get("event") == "artifact_signed":
                for endorsed, details in bodies[fields["body"]]:
                    if endorsed in rows and rows[endorsed]["signed_ns"] is None:
                        rows[endorsed].update(signed_ns=elapsed, endorsement_view=details.get("view"), endorsement_slot=details.get("slot"), endorsement_class=details.get("class"))
            if kind == "frame_sent" and fields.get("accepted"):
                body = votes.get(frames.get(fields.get("frame_digest")))
                for endorsed, _ in bodies.get(body, []):
                    if endorsed in rows and rows[endorsed]["send_ns"] is None:
                        rows[endorsed]["send_ns"] = elapsed
            if kind in {"finalized_tip", "historical_tip"} and block:
                visited = set()
                while block and block not in visited:
                    visited.add(block)
                    if block in rows and rows[block]["finality_ns"] is None:
                        rows[block].update(finality_ns=elapsed, finality_view=fields.get("view", fields.get("trigger_view")), finality_proof=fields.get("proof", fields.get("history")), finality_observation=kind, finality_class=("extension_deferred" if kind == "historical_tip" else "extension_in_view") if block[1] > fields["proposed_height"] else "proposal")
                    parent = parents.get(block)
                    block = (block[0], block[1]-1, parent) if parent and block[1] > 0 else None
        result.extend(rows.values())
    summary["cohort_blocks"] = len(starts)
    summary["missing_block_node_events"] = {key: sum(row[key] is None for row in result) for key in keys}
    summary["join_note"] = "Send means local p2p acceptance by at least one peer, not remote receipt. Producer-local blocks need not have a network receipt. Historical finality timestamps are validated marshal history-opening observations, potentially later than consensus knowledge. Null outcomes remain censored or lack captured ancestry; transport completeness alone does not establish complete block outcomes."
    return result


def view_rows(captures):
    result = []
    for header, events, _ in captures:
        artifacts, frames, rows = {}, {}, {}
        decoded = [(event, {k: scalar(v) for k, v in event["fields"].items()}) for event in events]
        for event, fields in decoded:
            if event["kind"] in {"proposal_block", "vote_body"}:
                artifacts[fields["artifact"]] = (fields["view"], "proposal" if event["kind"] == "proposal_block" else "vote")
            if event["kind"] == "artifact_framed":
                frames[fields["frame_digest"]] = fields["artifact"]
        for event, fields in sorted(decoded, key=lambda pair: pair[0]["elapsed_ns"]):
            kind = event["kind"]
            if kind == "vote_pacing_wait":
                row = rows.setdefault(fields["view"], {"node": header["node"], "view": fields["view"]})
                row.update(requested_wait=fields.get("requested_wait"), deadline_wall=fields.get("deadline_wall"), pacing_observed_ns=event["elapsed_ns"])
            artifact = fields.get("artifact") if kind == "artifact_received" else frames.get(fields.get("frame_digest")) if kind == "frame_sent" and fields.get("accepted") else None
            if artifact in artifacts:
                view, category = artifacts[artifact]
                row = rows.setdefault(view, {"node": header["node"], "view": view})
                if kind == "artifact_received" and category == "proposal":
                    row.setdefault("proposal_receipt_ns", fields.get("received_elapsed_ns"))
                elif kind == "frame_sent":
                    row.setdefault(f"{category}_send_ns", event["elapsed_ns"])
        result.extend(rows.values())
    return result


def write_rows(path, rows):
    if rows:
        with path.open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=sorted(set().union(*(row.keys() for row in rows))))
            writer.writeheader()
            writer.writerows(rows)


def read_capture(path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as source:
        records = [json.loads(line) for line in source if line.strip()]
    if not records or records[0].get("type") != "header":
        raise ValueError(f"{path}: missing header")
    header = records[0]
    errors = []
    events = [row for row in records if row.get("type") == "event"]
    footers = [row for row in records if row.get("type") == "footer"]
    if sum(row.get("type") == "header" for row in records) != 1:
        errors.append("multiple process headers")
    if any(row.get("type") not in {"header", "event", "footer", "wall_anchor"} for row in records):
        errors.append("unknown record type")
    if len(footers) != 1 or records[-1].get("type") != "footer":
        errors.append("missing or repeated terminal footer")
        footer = {}
    else:
        footer = footers[0]
        if not footer.get("complete"):
            errors.append("capture did not complete")
        for key in ("dropped_full", "dropped_oversized", "dropped_closed", "dropped_io"):
            if footer.get(key, 0):
                errors.append(f"{key}={footer[key]}")
        for key in ("attempts", "accepted", "written"):
            if footer.get(key) != len(events):
                errors.append(f"{key} does not match event count")
    sequences = sorted(row["seq"] for row in events)
    if sequences != list(range(len(events))):
        errors.append("duplicate or missing event sequence")
    counts = collections.Counter(row["kind"] for row in events)
    if counts["artifact_omitted"]:
        errors.append("canonical artifacts omitted")
    anchors = [row["wall_unix_ns"] - row["elapsed_ns"] for row in records if row.get("type") == "wall_anchor"]
    header["wall_anchor_spread_ns"] = max(anchors) - min(anchors) if anchors else None
    return header, events, footer, errors


def analyze(paths, nodes, minimum_seconds):
    captures = []
    errors = []
    seen = set()
    for path in paths:
        header, events, footer, failures = read_capture(path)
        node = header["node"]
        if node in seen:
            errors.append(f"node {node}: multiple captures/processes")
        seen.add(node)
        errors.extend(f"node {node}: {failure}" for failure in failures)
        captures.append((header, events, footer))
    if seen != set(nodes):
        errors.append(f"node set differs: missing={sorted(set(nodes)-seen)}, unexpected={sorted(seen-set(nodes))}")
    start = max(h["wall_unix_ns"] + h["warmup_ns"] for h, _, _ in captures)
    end = min(h["wall_unix_ns"] + h["warmup_ns"] + h["cohort_ns"] for h, _, _ in captures)
    if end - start < minimum_seconds * 1_000_000_000:
        errors.append("common cohort is shorter than the requested minimum")
    summary = {
        "transport_complete": not errors,
        "errors": errors,
        "common_cohort_start_unix_ns": start,
        "common_cohort_end_unix_ns": end,
        "common_cohort_seconds": max(0, end-start) / 1_000_000_000,
        "clock_note": "Wall anchors align cohort selection approximately; do not interpret cross-node differences as exact transit delays without clock-offset bounds.",
        "nodes": [{"node": h["node"], "events": len(events),
                   "kinds": dict(collections.Counter(e["kind"] for e in events)),
                   "footer": footer} for h, events, footer in captures],
    }
    return summary, captures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", type=Path, nargs="+")
    parser.add_argument("--nodes", required=True, help="comma-separated expected node identities")
    parser.add_argument("--minimum-seconds", type=float, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary, captures = analyze(args.captures, [int(n) for n in args.nodes.split(",")], args.minimum_seconds)
    blocks = block_rows(summary, captures)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    write_rows(args.output / "blocks.csv", blocks)
    write_rows(args.output / "views.csv", view_rows(captures))
    with (args.output / "events.csv").open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["node", "seq", "elapsed_ns", "approx_unix_ns", "phase", "kind", "fields"])
        for header, events, _ in captures:
            for event in sorted(events, key=lambda e: e["seq"]):
                writer.writerow([header["node"], event["seq"], event["elapsed_ns"],
                                 header["wall_unix_ns"] + event["elapsed_ns"],
                                 event["phase"], event["kind"], json.dumps(event["fields"])])
    print(json.dumps(summary, indent=2))
    return 0 if summary["transport_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
