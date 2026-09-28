import json
from pathlib import Path
import tempfile
import unittest

from analyze_capture import analyze, block_rows


class CaptureTests(unittest.TestCase):
    def test_joins_only_signed_bodies_and_exact_finalized_ancestry(self):
        def event(kind, elapsed, **fields):
            return dict(kind=kind, elapsed_ns=elapsed, fields=fields)
        block = dict(chain="0", height="1", digest="aa")
        events = [
            event("block_constructed", 1, **block, parent="00", submission_unix_ns="1"),
            event("endorsement_built", 2, **block, body="abandoned", view="1"),
            event("endorsement_built", 3, **block, body="used", view="2", slot="1", **{"class": '"extension"'}),
            event("vote_body", 4, body="used", artifact="signed", **{"event": '"artifact_signed"'}),
            event("artifact_framed", 5, artifact="signed", frame_digest="frame"),
            event("frame_sent", 6, frame_digest="frame", accepted="false"),
            event("frame_sent", 7, frame_digest="frame", accepted="true"),
            event("finalized_tip", 8, chain="0", height="1", digest="wrong", view="2", proposed_height="0"),
            event("historical_tip", 9, **block, trigger_view="3", history="history", proposed_height="0"),
        ]
        summary = dict(common_cohort_start_unix_ns=0, common_cohort_end_unix_ns=10)
        row, = block_rows(summary, [(dict(node=0), events, {})])
        self.assertEqual(row["signed_ns"], 4)
        self.assertEqual(row["send_ns"], 7)
        self.assertEqual(row["endorsement_view"], 2)
        self.assertEqual(row["finality_ns"], 9)
        self.assertEqual(row["finality_class"], "extension_deferred")

    def capture(self, directory, node=0, offset=0, gap=False, footer=True):
        rows = [dict(type="header", schema=1, node=node, wall_unix_ns=offset,
                     warmup_ns=0, cohort_ns=20_000_000_000, drain_ns=10_000_000_000),
                dict(type="event", seq=1 if gap else 0, elapsed_ns=1,
                     phase="cohort", kind="block_constructed", fields={})]
        if footer:
            rows.append(dict(type="footer", complete=True, attempts=1, accepted=1, written=1))
        path = Path(directory) / f"{node}.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return path

    def test_complete_transport_does_not_claim_complete_block_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, _ = analyze([self.capture(directory)], [0], 10)
            self.assertTrue(summary["transport_complete"])
            self.assertNotIn("outcomes_complete", summary)

    def test_missing_node(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, _ = analyze([self.capture(directory)], [0, 1], 10)
            self.assertFalse(summary["transport_complete"])

    def test_gap_and_truncated_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, _ = analyze([self.capture(directory, gap=True, footer=False)], [0], 10)
            self.assertIn("node 0: duplicate or missing event sequence", summary["errors"])
            self.assertIn("node 0: missing or repeated terminal footer", summary["errors"])

    def test_insufficient_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [self.capture(directory), self.capture(directory, node=1, offset=15_000_000_000)]
            summary, _ = analyze(paths, [0, 1], 10)
            self.assertEqual(summary["common_cohort_seconds"], 5)
            self.assertFalse(summary["transport_complete"])


if __name__ == "__main__":
    unittest.main()
