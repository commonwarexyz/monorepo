import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("publication.py")
SPEC = importlib.util.spec_from_file_location("publication", MODULE_PATH)
publication = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(publication)


class ValidateRawSamplesTest(unittest.TestCase):
    def write(self, records):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "stdout.log"
        path.write_text("".join(json.dumps(record) + "\n" for record in records))
        return path

    @staticmethod
    def records():
        metadata = {
            "record": "raw_metadata",
            "kind": "activity_verify",
            "name": "presence/H=0 R=1000",
            "boundary": "decoded_lookup_to_resolve_result",
            "fixture": "standalone_rows_without_payment_entries",
            "samples": 3,
            "iterations_per_sample": 1000,
            "lookup_bytes": 381,
            "head_bytes": 48,
            "expected_present": True,
        }
        samples = [
            {
                "record": "raw_sample",
                "kind": "activity_verify",
                "name": metadata["name"],
                "sample": index,
                "iterations": 1000,
                "total_ns": 1_000_000 + index,
                "verified": True,
            }
            for index in range(3)
        ]
        return [metadata, *samples]

    def test_accepts_complete_samples(self):
        observed = publication.validate_raw_samples(
            self.write(self.records()),
            "activity_verify",
            3,
            "decoded_lookup_to_resolve_result",
        )
        self.assertEqual(list(observed), ["presence/H=0 R=1000"])

    def test_rejects_missing_sample(self):
        with self.assertRaisesRegex(RuntimeError, "sample count mismatch"):
            publication.validate_raw_samples(
                self.write(self.records()[:-1]),
                "activity_verify",
                3,
                "decoded_lookup_to_resolve_result",
            )

    def test_rejects_boundary_change(self):
        records = self.records()
        records[0]["boundary"] = "fixture_to_result"
        with self.assertRaisesRegex(RuntimeError, "metadata contract mismatch"):
            publication.validate_raw_samples(
                self.write(records),
                "activity_verify",
                3,
                "decoded_lookup_to_resolve_result",
            )

    def test_rejects_missing_benchmark(self):
        with self.assertRaisesRegex(RuntimeError, "benchmark inventory mismatch"):
            publication.validate_raw_samples(
                self.write(self.records()),
                "activity_verify",
                3,
                "decoded_lookup_to_resolve_result",
                expected_names={"presence/H=0 R=1000", "absence/H=0 R=1000"},
            )

    def test_rejects_boolean_duration(self):
        records = self.records()
        records[1]["total_ns"] = True
        with self.assertRaisesRegex(RuntimeError, "sample contract mismatch"):
            publication.validate_raw_samples(
                self.write(records),
                "activity_verify",
                3,
                "decoded_lookup_to_resolve_result",
            )


class ActivityRawNamesTest(unittest.TestCase):
    def test_matches_native_empty_and_single_row_inventories(self):
        prefix = "bajillion::native_proofs::activity_verify/"
        self.assertEqual(
            publication.activity_raw_names(0, 0),
            {prefix + "absence_empty/H=0 R=0 operations=2 floor=0"},
        )
        self.assertEqual(
            publication.activity_raw_names(0, 1),
            {
                prefix + "presence/H=0 R=1 operations=3 floor=0",
                prefix + "absence_left/H=0 R=1 operations=3 floor=0",
                prefix + "absence_right/H=0 R=1 operations=3 floor=0",
            },
        )

    def test_prior_history_includes_its_commit(self):
        prefix = "bajillion::native_proofs::activity_verify/"
        self.assertEqual(
            publication.activity_raw_names(7, 1),
            {
                prefix + "presence/H=7 R=1 operations=11 floor=0",
                prefix + "absence_left/H=7 R=1 operations=11 floor=0",
                prefix + "absence_right/H=7 R=1 operations=11 floor=0",
            },
        )


class AggregateChecksTest(unittest.TestCase):
    def scaling_inventory(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        fixtures = {
            "001-sizes-1000000-1000-512-1/stdout.log": (
                "clearing sizes: root_bundle_bytes=184 descriptor_bytes=192 "
                "header_certificate_bytes=101 "
                "header_roots_withdrawal_total_certificate_bytes=293\n"
                "clearing withdrawal claim: output_bytes=64\n"
            ),
            "002-activity-H0-R1000-check/stdout.log": (
                "native_activity presence lookup_bytes=128 head_bytes=48\n"
            ),
            "003-challenge-1000000-1000-512-1/stdout.log": (
                "complete challenge_bytes=256\n"
            ),
            "004-ack-N1000000-A1000-B512-K1-W0-H0-timed/stdout.log": (
                '{"record":"ack_metadata","n":1000000,"a":1000,"b":512,'
                '"k":1,"w":0,"h":0,"withdrawal_output_bytes":0,'
                '"prepared_dealing_bytes":4096}\n'
            ),
        }
        for relative, contents in fixtures.items():
            path = root / relative
            path.parent.mkdir()
            path.write_text(contents)
        return root

    def test_scaling_inventory_does_not_require_signed_withdrawal_output(self):
        outputs = publication.aggregate_checks(
            self.scaling_inventory(), publication.DEFAULT_ACK
        )
        self.assertEqual(set(outputs), {"bytes.csv", "raw-checks.jsonl.gz"})

    def test_activity_scaling_does_not_require_unmeasured_payout_fixtures(self):
        root = self.scaling_inventory()
        path = root / "001-sizes-1000000-1000-512-1/stdout.log"
        sizes = path.read_text().splitlines()[0]
        path.unlink()
        path.parent.rmdir()
        challenge = root / "003-challenge-1000000-1000-512-1/stdout.log"
        challenge.write_text(sizes + "\n" + challenge.read_text())
        outputs = publication.aggregate_checks(root, publication.DEFAULT_ACK)
        self.assertEqual(set(outputs), {"bytes.csv", "raw-checks.jsonl.gz"})

    def test_withdrawal_case_requires_signed_output(self):
        with self.assertRaisesRegex(RuntimeError, "signed-pipeline output-frame"):
            publication.aggregate_checks(
                self.scaling_inventory(),
                (*publication.DEFAULT_ACK, (1_000_000, 1_000, 512, 1, 1, 0)),
            )

    def test_signed_output_requires_matching_workload(self):
        root = self.scaling_inventory()
        path = root / "005-ack-N1000000-A1000-B512-K1-W1-H0-timed"
        path.mkdir()
        (path / "stdout.log").write_text(json.dumps({
            "record": "ack_metadata", "n": 1_000_000, "a": 1_000,
            "b": 512, "k": 1, "w": 1, "h": 0,
            "withdrawal_output_bytes": 160,
        }) + "\n")
        outputs = publication.aggregate_checks(
            root, (*publication.DEFAULT_ACK, (1_000_000, 1_000, 512, 1, 1, 0)),
        )
        self.assertEqual(set(outputs), {"bytes.csv", "raw-checks.jsonl.gz"})
        with self.assertRaisesRegex(RuntimeError, "unexpectedly contains"):
            publication.aggregate_checks(root, publication.DEFAULT_ACK)


if __name__ == "__main__":
    unittest.main()
