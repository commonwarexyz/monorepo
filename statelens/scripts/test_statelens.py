#!/usr/bin/env python3
"""Tests for the parts of statelens.py that fail quietly.

Run with `just check-scripts`. Standard library only, like the script itself.

These cover the three defects that reached review, all of which produced a
plausible wrong answer rather than an error: a result tuple compared against an
integer, a SCIP range read as four elements when it has three, and an
assignment classified by the wrong sub-expression.
"""

import argparse
import io
import os
import contextlib
import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("statelens", HERE / "statelens.py")
sl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sl)


class IndexBuildResult(unittest.TestCase):
    """`run_logged` returns (code, tail); treating it as a code inverts the check."""

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        self.index = sl.index_path(self.sl_dir)
        self._which, self._run, self._say = sl.shutil.which, sl.run_logged, sl.say
        sl.shutil.which = lambda _name: "/usr/bin/rust-analyzer"
        sl.say = lambda *_args, **_kw: None

    def tearDown(self):
        sl.shutil.which, sl.run_logged, sl.say = self._which, self._run, self._say

    @staticmethod
    def output(command):
        """Where the command asks rust-analyzer to write the index."""
        return pathlib.Path(command[command.index("--output") + 1])

    def stub(self, command, _log, cwd=None, stdin_text=None, echo=True):
        """A successful run that leaves a real index behind, so the snapshot
        step runs exactly as it does in a campaign."""
        self.echoed = echo
        # SCIP paths are relative to the indexed crate, and index_load
        # prefixes them, so the file has to live under consensus/.
        (self.repo / "consensus/src").mkdir(parents=True, exist_ok=True)
        (self.repo / "consensus/src/x.rs").write_text("fn f() {}\n")
        self.output(command).write_bytes(scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9]))
        return 0, []

    def test_success_returns_the_index_path(self):
        sl.run_logged = self.stub
        self.assertEqual(sl.index_build(self.repo, self.sl_dir, "simplex"), self.index)

    def test_success_snapshots_the_indexed_sources(self):
        # Without the snapshot no query can rebase, so a successful build that
        # skipped it would leave the index quietly serving stale lines.
        sl.run_logged = self.stub
        sl.index_build(self.repo, self.sl_dir, "simplex")
        stored = json.loads(sl.snapshot_path(self.sl_dir).read_text())
        self.assertEqual(stored, {"consensus/src/x.rs": "fn f() {}\n"})

    def test_unreadable_index_still_returns_the_path(self):
        # The index is queryable even when the snapshot cannot be taken, and the
        # snapshot of the index it replaced must not stay to rebase its lines.
        def stub(command, _log, cwd=None, stdin_text=None, echo=True):
            self.output(command).write_bytes(b"\x1f\x8bnot protobuf")
            return 0, []

        sl.snapshot_path(self.sl_dir).write_text('{"consensus/src/old.rs": ""}')
        sl.run_logged = stub
        self.assertEqual(sl.index_build(self.repo, self.sl_dir, "simplex"), self.index)
        self.assertFalse(sl.snapshot_path(self.sl_dir).exists())

    def test_a_failed_build_leaves_the_previous_index_whole(self):
        # rust-analyzer writes as it goes, so a build that fails halfway must not
        # leave a truncated index where the previous one was.
        previous = scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9])
        self.index.write_bytes(previous)
        sl.snapshot_path(self.sl_dir).write_text("{}")

        def stub(command, _log, cwd=None, stdin_text=None, echo=True):
            self.output(command).write_bytes(previous[:7])
            return 1, ["error: interrupted"]

        sl.run_logged = stub
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "qmdb"))
        self.assertEqual(self.index.read_bytes(), previous)
        self.assertEqual(sl.snapshot_path(self.sl_dir).read_text(), "{}")
        self.assertEqual(list((self.sl_dir / "extract").glob("*.new")), [])

    def test_a_campaign_whose_build_fails_answers_from_no_index(self):
        # A consensus index left by an earlier campaign would otherwise answer the
        # queries of a qmdb campaign whose own build failed.
        (self.repo / "consensus/src").mkdir(parents=True)
        (self.repo / "consensus/src/x.rs").write_text("fn f() {}\n")
        self.index.write_bytes(scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9]))
        sl.snapshot_write(self.repo, self.sl_dir, ["consensus/src/x.rs"])
        sl.run_logged = lambda *_a, **_kw: (1, ["simulated failure"])
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.repo, campaign.sl_dir, campaign.profile_name = self.repo, self.sl_dir, "qmdb"
        with contextlib.redirect_stdout(io.StringIO()):
            campaign.code_index()
        self.assertFalse(self.index.exists())
        self.assertFalse(sl.snapshot_path(self.sl_dir).exists())
        saved = sl.repo_root
        sl.repo_root = lambda: self.repo
        self.addCleanup(setattr, sl, "repo_root", saved)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sl.main(["code", "defs", "sym", "--tests"]), 1)

    def test_nonzero_exit_returns_none(self):
        sl.run_logged = lambda *_a, **_kw: (1, ["error"])
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))

    def test_zero_exit_but_no_file_returns_none(self):
        sl.run_logged = lambda *_a, **_kw: (0, [])
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))

    def test_missing_rust_analyzer_returns_none(self):
        sl.shutil.which = lambda _name: None
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))

    def test_rust_analyzer_output_stays_off_the_console(self):
        # rust-analyzer logs ERROR lines for definitions in macro-declared
        # modules and keeps going; on a console they read as a failure, and an
        # operator interrupted a campaign over them.
        sl.run_logged = self.stub
        sl.index_build(self.repo, self.sl_dir, "simplex")
        self.assertFalse(self.echoed, "the index build must not echo rust-analyzer")

    def test_a_failed_build_shows_why(self):
        sl.run_logged = lambda *_a, **_kw: (1, ["error: could not load the workspace"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))
        self.assertIn("could not load the workspace", out.getvalue())


def packed(*values):
    """Encode ints as a protobuf packed repeated field."""
    out = bytearray()
    for value in values:
        while True:
            byte = value & 0x7F
            value >>= 7
            out.append(byte | (0x80 if value else 0))
            if not value:
                break
    return bytes(out)


class LoggedRuns(unittest.TestCase):
    """`run_logged` with `echo` off still has to keep the whole output in the log
    and return the tail, or a quiet step would hide its own failure."""

    def run_quiet(self, echo):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        log = directory / "run.log"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code, tail = sl.run_logged(
                [sys.executable, "-c", "print('one'); print('two')"], log, directory, echo=echo
            )
        return code, tail, log.read_text(), out.getvalue()

    def test_echo_off_writes_the_log_and_not_the_console(self):
        code, tail, log, console = self.run_quiet(echo=False)
        self.assertEqual(code, 0)
        self.assertEqual(tail, ["one", "two"])
        self.assertIn("one\ntwo\n", log)
        self.assertEqual(console, "")

    def test_echo_on_writes_both(self):
        _code, _tail, log, console = self.run_quiet(echo=True)
        self.assertIn("one\ntwo\n", log)
        self.assertEqual(console, "one\ntwo\n")


class ScipRanges(unittest.TestCase):
    """A range collapses to three elements on one line, where [2] is a column."""

    def test_three_element_range_round_trips(self):
        self.assertEqual(sl.scip_packed(packed(69, 4, 28)), [69, 4, 28])

    def test_four_element_range_round_trips(self):
        self.assertEqual(sl.scip_packed(packed(689, 4, 698, 5)), [689, 4, 698, 5])

    def test_multi_byte_varints(self):
        self.assertEqual(sl.scip_packed(packed(1, 300, 70000)), [1, 300, 70000])


def tag(field, wire):
    return packed((field << 3) | wire)


def length_delimited(field, payload):
    return tag(field, 2) + packed(len(payload)) + payload


def scip_index(relative, symbol, span, enclosing, roles=1):
    """The smallest SCIP index holding one definition occurrence."""
    occurrence = (
        length_delimited(1, packed(*span))
        + length_delimited(2, symbol.encode())
        + tag(3, 0)
        + packed(roles)
        + length_delimited(7, packed(*enclosing))
    )
    document = length_delimited(1, relative.encode()) + length_delimited(2, occurrence)
    return length_delimited(2, document)


class ScipExtents(unittest.TestCase):
    """The end line of a definition, which `callers` and `callees` depend on."""

    def load(self, enclosing):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        path = directory / "i.scip"
        path.write_bytes(scip_index("src/x.rs", "sym", [69, 4, 28], enclosing))
        _occurrences, definitions, _names = sl.index_load(path)
        return definitions["sym"]

    def test_one_line_definition_does_not_end_before_it_starts(self):
        # [start line, start char, end char]: the third element is a column.
        self.assertEqual(self.load([69, 4, 28]), ("consensus/src/x.rs", 70, 70))

    def test_multi_line_definition_keeps_its_end_line(self):
        # [start line, start char, end line, end char]
        self.assertEqual(self.load([689, 4, 698, 5]), ("consensus/src/x.rs", 690, 699))


class SyntaxSites(unittest.TestCase):
    """Polarity comes from the token after the whole field expression."""

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.path = cls.tmp / "t.rs"
        cls.path.write_text(
            "struct S { armed: bool, items: Vec<u8> }\n"                 # 1
            "impl S {\n"                                                  # 2
            "    fn new() -> S { S { armed: false, items: vec![] } }\n"   # 3
            "    fn arm(&mut self) { self.armed = true; }\n"              # 4
            "    fn ready(&self) -> bool { self.armed }\n"                # 5
            "    fn armed(&self) -> bool { self.armed }\n"                # 6
            "    fn add(&mut self) { self.items.push(1); }\n"             # 7
            "    fn lend(&mut self) { fill(&mut self.items); }\n"         # 8
            "    fn count(&self) -> usize { self.items.len() }\n"         # 9
            "    fn peek(&self) -> &Vec<u8> { &self.items }\n"             # 10
            "    fn set(&mut self) { self.items[0] = 2; }\n"               # 11
            "    fn bump(&mut self) { self.items[0] += 1; }\n"             # 12
            "    fn wrap(&mut self) { (self.items).push(3); }\n"           # 13
            "    fn lend_paren(&mut self) { fill(&mut (self.items)); }\n"  # 14
            "}\n"                                                         # 15
            "fn fill(_items: &mut Vec<u8>) {}\n"                          # 16
        )

    def test_classifies_write_init_and_read(self):
        writes, reads, inits, opaque, maybe = sl.ast_field_ops(self.path, "armed")
        self.assertEqual(opaque, [], "no macro bodies in this fixture")
        self.assertEqual(maybe, [], "a bool is never handed out here")
        # `self.armed = true` is a write, not a read of the `self` path.
        self.assertEqual(writes, [4])
        # a struct literal field is an initial value, not a write
        self.assertEqual(inits, [3])
        # the two bodies that read it; the method declaration on line 6 is a
        # different entity of the same spelling and is not counted
        self.assertEqual(reads, [5, 6])

    def test_a_field_handed_out_is_neither_a_read_nor_a_write(self):
        # The gap: `self.items.push(1)` and `fill(&mut self.items)` were reads, so
        # `--writes-only` left every mutation through a method out of the
        # transition inventory.
        writes, reads, inits, _opaque, maybe = sl.ast_field_ops(self.path, "items")
        # An assignment through an index is a write of the field.
        self.assertEqual(writes, [11, 12])
        self.assertEqual(inits, [3])
        # Parentheses around the receiver or the borrowed place change nothing.
        self.assertEqual(
            maybe,
            [(7, ".push(..)"), (8, "&mut"), (9, ".len(..)"), (13, ".push(..)"), (14, "&mut")],
        )
        self.assertEqual(reads, [10], "a shared borrow cannot write, so it stays a read")

    def test_a_write_through_a_projection_is_a_write_of_the_field(self):
        path = self.tmp / "p.rs"
        path.write_text(
            "struct Inner { count: u8 }\n"                        # 1
            "struct S { inner: Inner }\n"                         # 2
            "impl S {\n"                                          # 3
            "    fn set(&mut self) { self.inner.count = 1; }\n"   # 4
            "    fn add(&mut self) { self.inner.count += 1; }\n"  # 5
            "    fn get(&self) -> u8 { self.inner.count }\n"      # 6
            "}\n"                                                 # 7
        )
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "inner")
        self.assertEqual((writes, reads, maybe), ([4, 5], [6], []))
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "count")
        self.assertEqual((writes, reads, maybe), ([4, 5], [6], []))

    def test_derefs_and_tuple_assignments_reach_the_field(self):
        path = self.tmp / "d.rs"
        path.write_text(
            "struct S { boxed: Box<Vec<u8>>, items: Vec<u8>, n: u8 }\n"        # 1
            "impl S {\n"                                                        # 2
            "    fn clear_boxed(&mut self) { (*self.boxed).clear(); }\n"        # 3
            "    fn lend_boxed(&mut self) { fill(&mut *self.boxed); }\n"        # 4
            "    fn reset(&mut self) { *self.boxed = Box::new(vec![]); }\n"     # 5
            "    fn pair(&mut self) { (self.items, self.n) = (vec![], 0); }\n"  # 6
            "    fn neg(&self) -> i32 { -(self.n as i32) }\n"                   # 7
            "    fn both(&self) -> (u8, u8) { (self.n, self.n) }\n"             # 8
            "}\n"                                                               # 9
            "fn fill(_v: &mut Vec<u8>) {}\n"                                    # 10
        )
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "boxed")
        self.assertEqual((writes, reads, maybe), ([5], [], [(3, ".clear(..)"), (4, "&mut")]))
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "items")
        self.assertEqual((writes, reads, maybe), ([6], [], []))
        writes, reads, _inits, _opaque, maybe = sl.ast_field_ops(path, "n")
        self.assertEqual((writes, reads, maybe), ([6], [7, 8], []))

    def test_writes_only_keeps_the_maybe_sites(self):
        saved = sl.repo_root
        sl.repo_root = lambda: self.tmp
        self.addCleanup(setattr, sl, "repo_root", saved)
        out = io.StringIO()
        args = argparse.Namespace(
            query="sites", name="items", paths=["t.rs"], tests=True, writes_only=True
        )
        with contextlib.redirect_stdout(out):
            sl.cmd_ast(args)
        text = out.getvalue()
        self.assertIn("write  t.rs:11", text)
        self.assertIn("maybe  t.rs:7  .push(..)", text)
        self.assertIn("maybe  t.rs:8  &mut", text)
        self.assertNotIn("read", text)
        self.assertNotIn("init", text)


class Rebasing(unittest.TestCase):
    """Instrumentation moves lines, so an indexed line is not a current line."""

    ORIGINAL = (
        "pub struct Round { armed: bool }\n"
        "\n"
        "impl Round {\n"
        "    pub fn arm(&mut self) {\n"
        "        self.armed = true;\n"
        "    }\n"
        "}\n"
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        self.rel = "src/lib.rs"
        self.file = self.repo / self.rel
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text(self.ORIGINAL)
        sl.snapshot_write(self.repo, self.sl_dir, [self.rel])

    def rebaser(self):
        return sl.Rebaser(self.repo, self.sl_dir)

    def test_unchanged_file_keeps_its_lines(self):
        self.assertEqual(self.rebaser().place(self.rel, 5, "armed"), (5, ""))

    def test_insertion_above_moves_the_line(self):
        # an earlier batch inserts two lines above `arm`
        self.file.write_text(
            self.ORIGINAL.replace(
                "impl Round {", "impl Round {\n    // probe\n    fn note(&self) {}", 1
            )
        )
        where, note = self.rebaser().place(self.rel, 5, "armed")
        self.assertEqual((where, note), (7, "moved"))
        # and the name really is there now
        self.assertIn("armed", self.file.read_text().splitlines()[where - 1])

    def test_edited_line_is_reported_lost_not_guessed(self):
        self.file.write_text(self.ORIGINAL.replace("        self.armed = true;\n", ""))
        _where, note = self.rebaser().place(self.rel, 5, "armed")
        self.assertEqual(note, "lost")

    def test_report_names_the_changed_files(self):
        self.file.write_text(self.ORIGINAL.replace("impl Round {", "impl Round {\n", 1))
        rebaser = self.rebaser()
        rebaser.place(self.rel, 5)
        self.assertIn("1 indexed file(s) have changed", rebaser.report())

    def test_file_absent_from_the_snapshot_is_marked_not_trusted(self):
        # An empty or partial snapshot must not make a stale line look current.
        sl.snapshot_path(self.sl_dir).write_text("{}")
        rebaser = self.rebaser()
        self.assertEqual(rebaser.place(self.rel, 5, "armed"), (5, "unindexed"))
        self.assertIn("no snapshot", rebaser.report())

    def test_missing_snapshot_is_announced(self):
        sl.snapshot_path(self.sl_dir).unlink()
        self.assertIn("no source snapshot", self.rebaser().report())

    def test_test_boundary_uses_the_rebased_line(self):
        # production code above, `#[cfg(test)]` below; a hit on the last
        # production line must not become a test hit when lines shift.
        text = "fn a() {}\n" * 4 + "#[cfg(test)]\nmod t {}\n"
        self.file.write_text(text)
        sl.snapshot_write(self.repo, self.sl_dir, [self.rel])
        boundaries = {}
        self.assertFalse(sl.index_is_test(self.repo, boundaries, self.rel, 4))
        # insert two lines at the top: the old line 4 is now line 6, and the
        # boundary has moved from 5 to 7, so it is still production.
        self.file.write_text("// probe\n// probe\n" + text)
        where, _note = self.rebaser().place(self.rel, 4)
        self.assertEqual(where, 6)
        self.assertFalse(sl.index_is_test(self.repo, {}, self.rel, where))
        # without rebasing, line 4 would be compared against the new boundary
        self.assertFalse(sl.index_is_test(self.repo, {}, self.rel, 4))


class CommentAttribution(unittest.TestCase):
    """A doc comment is the first token of its item, so the item begins at the
    comment; searching forward first lands on the body's first statement."""

    SOURCE = (
        "struct S { armed: bool }\n"                    # 1
        "\n"                                            # 2
        "impl S {\n"                                    # 3
        "    /// Recovers the latch after a replay.\n"   # 4  doc -> FN at 4
        "    fn recover(&mut self) {\n"                  # 5
        "        let first = 1;\n"                       # 6
        "        // never clear it twice in one view\n"  # 7  in body -> stmt at 8
        "        self.armed = true;\n"                   # 8
        "        let _ = first;\n"                       # 9
        "    }\n"                                        # 10
        "}\n"                                            # 11
    )

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.path = cls.tmp / "t.rs"
        cls.path.write_text(cls.SOURCE)

    def notes(self, pattern):
        return sl.ast_notes(self.path, pattern)

    def test_doc_comment_names_its_function_not_a_nested_statement(self):
        found = self.notes("replay")
        self.assertEqual(len(found), 1, found)
        line, _text, item = found[0]
        self.assertEqual(line, 4)
        self.assertEqual(item, ("FN", 5 - 1))  # the FN begins at the doc comment

    def test_comment_in_a_body_names_what_follows_it(self):
        found = self.notes("never")
        self.assertEqual(len(found), 1, found)
        line, _text, item = found[0]
        self.assertEqual(line, 7)
        self.assertIsNotNone(item)
        self.assertEqual(item[1], 8)
        self.assertIn(item[0], ("EXPR_STMT", "LET_STMT"))


class MacroBodies(unittest.TestCase):
    """`rust-analyzer parse` does not expand macros, so a macro body is a bare
    token tree. A name there must be reported, not dropped."""

    SOURCE = (
        "macro_rules! pick { ($($t:tt)*) => { $($t)* } }\n"
        "struct S { armed: bool }\n"
        "impl S {\n"
        "    fn plain(&mut self) { self.armed = true; }\n"
        "    fn wrapped(&mut self) { pick! { self.armed = true; } }\n"
        "}\n"
    )

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.path = cls.tmp / "t.rs"
        cls.path.write_text(cls.SOURCE)

    def test_a_write_inside_a_macro_is_reported_as_unknown_not_dropped(self):
        writes, reads, inits, opaque, _maybe = sl.ast_field_ops(self.path, "armed")
        self.assertEqual(writes, [4], "the plain write")
        self.assertEqual(opaque, [5], "the write inside the macro body")
        self.assertNotIn(5, reads, "a macro-body site must not pass as a read")
        self.assertEqual(inits, [])


class Cleaning(unittest.TestCase):
    """`clean --yes` has to leave a checkout a next campaign will accept.

    Two ways it did not: `git checkout --` on an intent-to-add path succeeds and
    leaves an empty staged file, and `git checkout --` restores the index, so
    instrumentation the operator staged survived.
    """

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        for relative in (
            "consensus/src/simplex/mod.rs",
            "consensus/src/marshal/mod.rs",
            "consensus/fuzz/marshal/fuzz_targets/keep.rs",
        ):
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fn original() {}\n")
        self.run_git("init", "-q", ".")
        self.run_git("config", "user.email", "t@example.invalid")
        self.run_git("config", "user.name", "t")
        self.run_git("config", "commit.gpgsign", "false")
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "base")
        self._root, self._say = sl.repo_root, sl.say
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_a, **_kw: None

    def tearDown(self):
        sl.repo_root, sl.say = self._root, self._say

    def clean(self):
        return sl.cmd_clean(argparse.Namespace(yes=True))

    def status(self):
        return self.run_git("status", "--porcelain").strip()

    def test_agent_added_file_is_deleted(self):
        helper = self.repo / "consensus/src/simplex/helper.rs"
        helper.write_text("fn helper() {}\n")
        self.run_git("add", "--intent-to-add", "consensus/src/simplex/helper.rs")
        delete, restore, _roots = sl.clean_plan(self.repo)
        self.assertIn("consensus/src/simplex/helper.rs", delete)
        self.assertNotIn("consensus/src/simplex/helper.rs", restore)
        self.assertEqual(self.clean(), 0)
        self.assertFalse(helper.exists(), "an added file must be deleted, not emptied")
        self.assertEqual(self.status(), "")

    def test_untracked_file_is_deleted(self):
        stray = self.repo / "consensus/src/marshal/stray.rs"
        stray.write_text("fn stray() {}\n")
        self.assertEqual(self.clean(), 0)
        self.assertFalse(stray.exists())
        self.assertEqual(self.status(), "")

    def test_staged_instrumentation_is_restored_from_head(self):
        edited = self.repo / "consensus/src/simplex/mod.rs"
        edited.write_text("fn original() { sl_probe!(); }\n")
        self.run_git("add", "consensus/src/simplex/mod.rs")
        self.assertEqual(self.clean(), 0)
        self.assertNotIn("sl_probe", edited.read_text())
        self.assertEqual(self.status(), "", "the index must match HEAD too")

    def test_unstaged_edit_is_restored(self):
        edited = self.repo / "consensus/src/marshal/mod.rs"
        edited.write_text("fn original() { sl_assert!(); }\n")
        self.assertEqual(self.clean(), 0)
        self.assertNotIn("sl_assert", edited.read_text())

    def test_clean_tree_is_left_alone(self):
        self.assertEqual(self.clean(), 0)
        self.assertEqual(self.status(), "")

    def test_an_untracked_helper_directory_is_deleted(self):
        # Git collapses a wholly untracked directory to one `dir/` entry, and a
        # directory cannot be unlinked; `record()` has not run, so the files are
        # untracked.
        extra = self.repo / "consensus/src/simplex/extra"
        extra.mkdir()
        (extra / "helper.rs").write_text("fn helper() {}\n")
        (extra / "second.rs").write_text("fn second() {}\n")
        delete, _restore, _roots = sl.clean_plan(self.repo)
        self.assertIn("consensus/src/simplex/extra/helper.rs", delete)
        self.assertIn("consensus/src/simplex/extra/second.rs", delete)
        self.assertNotIn("consensus/src/simplex/extra/", delete)
        self.assertEqual(self.clean(), 0)
        self.assertFalse((extra / "helper.rs").exists())
        self.assertFalse(extra.exists(), "the emptied directory should go too")
        self.assertEqual(self.status(), "")

    def test_a_root_directory_is_never_removed(self):
        (self.repo / "consensus/src/simplex/stray.rs").write_text("fn s() {}\n")
        self.assertEqual(self.clean(), 0)
        self.assertTrue((self.repo / "consensus/src/simplex").is_dir())

    def test_a_qmdb_campaign_is_undone(self):
        for relative in (
            "storage/src/qmdb/mod.rs",
            "storage/Cargo.toml",
            "storage/fuzz/Cargo.toml",
            "storage/fuzz/fuzz_targets/qmdb_x.rs",
        ):
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("original\n")
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "storage")
        runtime = self.repo / sl.QMDB_RS
        runtime.write_text("//! runtime\n")
        self.run_git("add", "--intent-to-add", sl.QMDB_RS)
        variant = self.repo / "storage/fuzz/fuzz_targets/qmdb_x_statelens.rs"
        variant.write_text("fuzz_target!(|input: In| {});\n")
        for relative in ("storage/src/qmdb/mod.rs", "storage/Cargo.toml", "storage/fuzz/Cargo.toml"):
            (self.repo / relative).write_text("original\nedited\n")
        self.assertEqual(self.clean(), 0)
        self.assertEqual(self.status(), "")
        self.assertFalse(runtime.exists())
        self.assertFalse(variant.exists())
        self.assertEqual((self.repo / "storage/Cargo.toml").read_text(), "original\n")

    def test_all_four_kinds_at_once(self):
        (self.repo / "consensus/src/simplex/helper.rs").write_text("fn h() {}\n")
        self.run_git("add", "--intent-to-add", "consensus/src/simplex/helper.rs")
        (self.repo / "consensus/src/marshal/stray.rs").write_text("fn s() {}\n")
        (self.repo / "consensus/src/simplex/mod.rs").write_text("fn original() { a(); }\n")
        self.run_git("add", "consensus/src/simplex/mod.rs")
        (self.repo / "consensus/src/marshal/mod.rs").write_text("fn original() { b(); }\n")
        self.assertEqual(self.clean(), 0)
        self.assertEqual(self.status(), "")
        self.assertFalse((self.repo / "consensus/src/simplex/helper.rs").exists())
        self.assertFalse((self.repo / "consensus/src/marshal/stray.rs").exists())


class WorktreeScope(unittest.TestCase):
    """A Phase 1 agent can write anywhere in the operator's tree, so the whole
    worktree is watched, not only the invariant registry."""

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        (self.repo / "docs").mkdir(parents=True)
        (self.repo / "README.md").write_text("original\n")
        (self.repo / "docs/guide.md").write_text("original\n")
        (self.repo / "untracked").mkdir()
        self.run_git("init", "-q", ".")
        self.run_git("config", "user.email", "t@example.invalid")
        self.run_git("config", "user.name", "t")
        self.run_git("config", "commit.gpgsign", "false")
        self.run_git("add", "README.md", "docs/guide.md")
        self.run_git("commit", "-qm", "base")

    def changed(self, before, after):
        return sorted(
            path
            for path in set(before) | set(after)
            if before.get(path) != after.get(path)
        )

    def test_a_new_file_is_seen(self):
        before = sl.worktree_state(self.repo)
        (self.repo / "docs/stray.md").write_text("written by an agent\n")
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["docs/stray.md"])

    def test_a_modified_tracked_file_is_seen(self):
        before = sl.worktree_state(self.repo)
        (self.repo / "README.md").write_text("edited\n")
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["README.md"])

    def test_a_deleted_tracked_file_is_seen(self):
        before = sl.worktree_state(self.repo)
        (self.repo / "docs/guide.md").unlink()
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["docs/guide.md"])

    def test_a_second_edit_to_an_already_dirty_file_is_seen(self):
        # The status code stays ` M`, so only a digest catches this. It is the
        # normal case in a development checkout, which is already dirty.
        (self.repo / "README.md").write_text("the operator's own edit\n")
        before = sl.worktree_state(self.repo)
        self.assertIn("README.md", before)
        (self.repo / "README.md").write_text("the operator's edit, plus the agent's\n")
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["README.md"])

    def test_a_file_in_an_untracked_directory_is_seen(self):
        # Without -uall git collapses this to `untracked/` and a new file in it
        # would not change the report.
        (self.repo / "untracked/first.txt").write_text("one\n")
        before = sl.worktree_state(self.repo)
        (self.repo / "untracked/second.txt").write_text("two\n")
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)),
                         ["untracked/second.txt"])

    def test_an_unchanged_tree_reports_nothing(self):
        before = sl.worktree_state(self.repo)
        self.assertEqual(self.changed(before, sl.worktree_state(self.repo)), [])


class ExtractScope(unittest.TestCase):
    """`extract` must report what the agent wrote outside the registry.

    The prompt machinery is stubbed: what is under test is the scope check, not
    prompt composition.
    """

    def run_git(self, *args):
        return subprocess.run(
            ("git",) + args, cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "invariants/simplex").mkdir(parents=True)
        (self.repo / "README.md").write_text("original\n")
        self.run_git("init", "-q", ".")
        self.run_git("config", "user.email", "t@example.invalid")
        self.run_git("config", "user.name", "t")
        self.run_git("config", "commit.gpgsign", "false")
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "base")
        self.saved = {
            name: getattr(sl, name)
            for name in ("repo_root", "say", "load_config", "resolve_agent",
                         "extract_values", "compose", "agent_command", "run_logged",
                         "lint_paths", "registry_files")
        }
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_a, **_kw: None
        sl.load_config = lambda _d: {}
        sl.resolve_agent = lambda _c, _a: "claude"
        sl.extract_values = lambda *_a, **_kw: {"NEXT_ID": "INV-0001"}
        sl.compose = lambda *_a, **_kw: "prompt"
        sl.agent_command = lambda *_a, **_kw: ["true"]
        sl.lint_paths = lambda *_a, **_kw: 0
        sl.registry_files = lambda *_a, **_kw: []
        self.addCleanup(self.restore)

    def restore(self):
        for name, value in self.saved.items():
            setattr(sl, name, value)

    def extract(self, agent_does):
        def stub(_command, log, _cwd, stdin_text=None):
            pathlib.Path(log).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(log).write_text("stub\n")
            agent_does()
            return 0, []

        sl.run_logged = stub
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sl.cmd_extract(
                argparse.Namespace(agent=None, registry="simplex", kind="issue",
                                   sources=["x"], number=self.number)
            )
        return code, out.getvalue()

    number = None

    def write_invariants(self, count):
        def write():
            for index in range(count):
                (self.sl_dir / f"invariants/simplex/INV-{index + 1:04d}.md").write_text("x\n")
        return write

    def test_more_invariants_than_asked_for_is_a_problem(self):
        self.number = 1
        code, output = self.extract(self.write_invariants(2))
        self.assertEqual(code, 3, output)
        self.assertIn("more than the 1 asked for", output)

    def test_as_many_as_asked_for_is_clean(self):
        self.number = 2
        code, output = self.extract(self.write_invariants(2))
        self.assertEqual(code, 0, output)

    def test_a_number_below_one_is_refused(self):
        self.number = 0
        with self.assertRaises(sl.Abort):
            self.extract(lambda: None)

    def test_a_quiet_run_is_clean(self):
        code, output = self.extract(lambda: None)
        self.assertEqual(code, 0, output)

    def test_an_edit_outside_the_registry_is_reported(self):
        def touch_readme():
            (self.repo / "README.md").write_text("the agent edited this\n")

        code, output = self.extract(touch_readme)
        self.assertEqual(code, 3, output)
        self.assertIn("README.md", output)
        self.assertIn("outside invariants/", output)

    def test_a_new_file_outside_the_registry_is_reported(self):
        def write_stray():
            (self.repo / "consensus").mkdir(parents=True, exist_ok=True)
            (self.repo / "consensus/stray.rs").write_text("fn stray() {}\n")

        code, output = self.extract(write_stray)
        self.assertEqual(code, 3, output)
        self.assertIn("consensus/stray.rs", output)



class ExtractionInputs(unittest.TestCase):
    """What `--number` asks of the analyst, which sources `comment` accepts, and where
    invariants go, so a private finding never lands in the tracked registry."""

    REPO = HERE.parents[1]

    def test_the_count_is_a_ceiling_never_a_quota(self):
        self.assertIn("as many invariants as the sources justify", sl.extraction_count(None))
        text = sl.extraction_count(10)
        self.assertIn("Write 10 invariant(s)", text)
        self.assertIn("write fewer", text)
        self.assertIn("Never invent", text)

    def test_findings_go_to_the_local_registry_and_git_ignores_it(self):
        self.assertEqual(
            sl.extraction_destination("kb", "qmdb"), sl.SL / "invariants.local" / "qmdb"
        )
        self.assertEqual(sl.extraction_destination("comment", "qmdb"), sl.SL / "invariants" / "qmdb")
        ignored = (HERE.parent / ".gitignore").read_text().splitlines()
        self.assertIn("invariants.local/", ignored)

    def test_comment_sources_are_the_registry_code(self):
        sl.check_comment_sources(self.REPO, "qmdb", ["storage/src/qmdb/mod.rs:1-93"])
        sl.check_comment_sources(self.REPO, "qmdb", ["storage/src/qmdb/current"])
        with self.assertRaises(sl.Abort) as caught:
            sl.check_comment_sources(self.REPO, "qmdb", ["consensus/src/simplex/mod.rs"])
        self.assertNotIn("kb", str(caught.exception))

    def test_a_corpus_root_given_as_a_comment_source_points_to_the_kb_kind(self):
        corpus = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, corpus, True)
        with self.assertRaises(sl.Abort) as caught:
            sl.check_comment_sources(self.REPO, "qmdb", ["storage/src/qmdb/mod.rs", str(corpus)])
        self.assertIn(f"just extract-invariants --registry qmdb kb {corpus}", str(caught.exception))

    def test_ids_and_bindings_span_the_local_registry(self):
        sl_dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, sl_dir, True)
        for relative in (
            "invariants/qmdb/INV-0002.md",
            "invariants.local/qmdb/INV-0005.md",
            "invariants.local/qmdb/INV-0001.md",
            "false-invariants/qmdb/FALSE-0003.md",
        ):
            (sl_dir / relative).parent.mkdir(parents=True, exist_ok=True)
            (sl_dir / relative).write_text("x\n")
        self.assertEqual(sl.next_invariant_id(sl_dir), "INV-0006")
        bound = [path.name for path in sl.registry_invariants(sl_dir, "qmdb", with_false=True)]
        self.assertEqual(bound, ["INV-0001.md", "INV-0002.md", "INV-0005.md", "FALSE-0003.md"])
        self.assertNotIn("FALSE-0003.md", [p.name for p in sl.registry_invariants(sl_dir, "qmdb")])

    def test_the_lint_accepts_the_local_registry(self):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        path = root / "invariants.local" / "qmdb" / "INV-0001.md"
        path.parent.mkdir(parents=True)
        path.write_text(
            "---\nid: INV-0001\ntitle: A title\nsource_kind: kb\nsource_ref: finding QMDB-1\n"
            "scope: [database]\n---\n\n## Statement\nThe database shall keep its root.\n\n"
            "## Rationale\nIt must.\n\n## Evidence\nA finding.\n"
        )
        self.assertEqual(sl.lint_file(path), [])


class KbExtraction(unittest.TestCase):
    """`extract kb` reads the findings of a registry's scope through the `kb` commands
    and writes what it derives to the local registry, never the tracked one."""

    FINDING = (
        "# {title}\n\n```claim\nmodule: {module}\nsummary: {summary}\n"
        "severity_current: high\nremediation_status: fixed\n```\n\n## Root Cause\nSomething.\n"
    )

    def run_git(self, *args):
        subprocess.run(("git",) + args, cwd=self.repo, capture_output=True, check=True)

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.corpus = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.corpus, True)
        self.sl_dir = self.repo / sl.SL
        for part in ("prompts", "templates"):
            shutil.copytree(HERE.parent / part, self.sl_dir / part)
        (self.repo / "README.md").write_text("x\n")
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            self.run_git(*args)
        for state, identifier, module, summary in (
            ("valid", "QMDB-1", "storage/qmdb/any", "stale batch applied"),
            ("valid", "SIMPLEX-1", "consensus/simplex", "vote twice"),
        ):
            path = self.corpus / "findings" / state / f"{identifier}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.FINDING.format(title=identifier, module=module, summary=summary))
        saved = {name: getattr(sl, name) for name in
                 ("repo_root", "say", "resolve_agent", "agent_command", "run_logged")}
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])
        environment = os.environ.get("STATELENS_KB")
        self.addCleanup(
            lambda: os.environ.pop("STATELENS_KB", None) if environment is None
            else os.environ.__setitem__("STATELENS_KB", environment)
        )
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_a, **_kw: None
        sl.resolve_agent = lambda _c, _a: "claude"
        self.phases = []
        sl.agent_command = lambda _c, _a, phase, _r: self.phases.append(phase) or ["true"]

    def extract(self, write):
        seen = {}

        def agent(_command, log, _cwd, stdin_text=None):
            pathlib.Path(log).write_text("stub\n")
            seen["prompt"] = stdin_text
            seen["kb"] = os.environ.get("STATELENS_KB")
            write()
            return 0, []

        sl.run_logged = agent
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sl.cmd_extract(argparse.Namespace(
                agent=None, registry="qmdb", kind="kb", sources=[str(self.corpus)], number=1
            ))
        return code, out.getvalue(), seen

    def invariant(self):
        path = self.sl_dir / "invariants.local/qmdb/INV-0001.md"
        path.write_text(
            "---\nid: INV-0001\ntitle: No stale batch is applied\nsource_kind: kb\n"
            "source_ref: finding QMDB-1\nscope: [database, any]\n---\n\n## Statement\n"
            "The database shall not apply a stale batch.\n\n## Rationale\nIt corrupts.\n\n"
            "## Evidence\nA finding.\n"
        )

    def test_the_findings_in_scope_reach_the_agent_and_the_result_stays_local(self):
        code, output, seen = self.extract(self.invariant)
        self.assertEqual(code, 0, output)
        self.assertEqual(self.phases, ["kb"])
        self.assertEqual(seen["kb"], str(self.corpus))
        prompt = seen["prompt"]
        self.assertIn("`QMDB-1`: valid", prompt)
        self.assertNotIn("SIMPLEX-1", prompt)
        self.assertIn("statelens/invariants.local/qmdb/<ID>.md", prompt)
        self.assertIn("kb show --registry qmdb", prompt)
        self.assertIn("Write 1 invariant(s)", prompt)
        self.assertNotIn("{{", prompt)
        self.assertFalse((self.sl_dir / "invariants" / "qmdb").exists())

    def test_a_write_to_the_tracked_registry_is_a_problem(self):
        def tracked():
            path = self.sl_dir / "invariants/qmdb/INV-0001.md"
            path.parent.mkdir(parents=True)
            path.write_text("x\n")

        code, output, _seen = self.extract(tracked)
        self.assertEqual(code, 3, output)
        self.assertIn("outside the registry invariants.local/qmdb/", output)

    def test_a_corpus_without_findings_in_scope_is_refused(self):
        shutil.rmtree(self.corpus / "findings" / "valid")
        (self.corpus / "findings" / "valid").mkdir()
        with self.assertRaises(sl.Abort) as caught:
            self.extract(lambda: None)
        self.assertIn("names a module of the qmdb registry", str(caught.exception))
class TestCodeRanges(unittest.TestCase):
    """`#[cfg(test)]` marks an item, not a file suffix.

    `simplex/actors/voter/mod.rs` gates one re-export at line 18 and declares
    production configuration after it, with its test module only at 52, so a
    suffix rule labelled the configuration as test code.
    """

    SOURCE = (
        "use core::num::NonZeroUsize;\n"          # 1
        "pub use ingress::Mailbox;\n"             # 2
        "#[cfg(test)]\n"                          # 3  gates only line 4
        "pub use ingress::Message;\n"             # 4
        "\n"                                      # 5
        "pub struct Config {\n"                   # 6  production
        "    pub scheme: u8,\n"                   # 7  production
        "}\n"                                     # 8
        "\n"                                      # 9
        "impl Config {\n"                         # 10
        "    #[cfg(test)]\n"                      # 11 gates only lines 11-12
        "    pub fn only_for_tests() {}\n"        # 12
        "    pub fn used_in_production() {}\n"    # 13 production
        "}\n"                                     # 14
        "\n"                                      # 15
        "#[cfg(test)]\n"                          # 16 the real test module
        "mod tests {\n"                           # 17
        "    fn t() {}\n"                         # 18
        "}\n"                                     # 19
    )

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.rel = "consensus/src/x/mod.rs"
        (self.repo / self.rel).parent.mkdir(parents=True)
        (self.repo / self.rel).write_text(self.SOURCE)

    def is_test(self, line):
        return sl.index_is_test(self.repo, {}, self.rel, line)

    def test_a_gated_re_export_is_test_code(self):
        self.assertTrue(self.is_test(4))

    def test_production_code_after_a_gated_re_export_is_not_test_code(self):
        # the defect: a suffix rule marked everything from line 3 onwards
        self.assertFalse(self.is_test(6), "the struct")
        self.assertFalse(self.is_test(7), "its field")

    def test_a_gated_method_is_test_code_but_its_neighbour_is_not(self):
        self.assertTrue(self.is_test(12))
        self.assertFalse(self.is_test(13))

    def test_the_test_module_is_test_code(self):
        self.assertTrue(self.is_test(17))
        self.assertTrue(self.is_test(18))

    def test_ranges_are_the_item_extents(self):
        self.assertEqual(
            sl.index_test_ranges(self.repo, self.rel), [(3, 4), (11, 12), (16, 19)]
        )

    def test_a_mocks_file_is_test_support_throughout(self):
        other = "consensus/src/x/mocks.rs"
        (self.repo / other).write_text("pub fn harness() {}\n")
        self.assertTrue(sl.index_is_test(self.repo, {}, other, 1))


class KbDocuments(unittest.TestCase):
    """`kb show` on a document must print the document.

    A document has no claim block and no state-bearing sections, so rendering it
    as a finding printed an empty shell of both.
    """

    def setUp(self):
        self.corpus = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.corpus, True)
        (self.corpus / "kb").mkdir()
        self.body = "# Certification design\n\nNullification does not cancel it.\n"
        (self.corpus / "kb/design.md").write_text(self.body)
        # A repository of its own: the query writes its index under the repository, and
        # must not replace the operator's statelens/extract/kb-index.json.
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        (self.repo / sl.SL / "extract").mkdir(parents=True)
        self.saved = {name: getattr(sl, name) for name in ("repo_root", "say")}
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_a, **_kw: None
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in self.saved.items()])

    def show(self, section=None):
        out = io.StringIO()
        args = argparse.Namespace(
            query="show", registry="simplex", identifier="kb/design.md",
            section=(section.split() if section else []),
        )
        old = os.environ.get("STATELENS_KB")
        os.environ["STATELENS_KB"] = str(self.corpus)
        try:
            with contextlib.redirect_stdout(out):
                code = sl.cmd_kb(args)
        finally:
            if old is None:
                del os.environ["STATELENS_KB"]
            else:
                os.environ["STATELENS_KB"] = old
        return code, out.getvalue()

    def test_show_prints_the_document_body(self):
        code, output = self.show()
        self.assertEqual(code, 0, output)
        self.assertIn("Nullification does not cancel it.", output)
        self.assertIn("(document)", output)
        self.assertNotIn("no claim block", output)

    def test_asking_for_a_section_is_refused_clearly(self):
        with self.assertRaises(sl.Abort) as caught:
            self.show("Root Cause")
        self.assertIn("is a document, which has no sections", str(caught.exception))


def scip_document(relative, occurrences, names=None):
    """A SCIP index of one document holding several occurrences.

    Each occurrence is (symbol, span, enclosing or None, roles). `names` maps
    a symbol to the display name its symbol information carries.
    """
    body = length_delimited(1, relative.encode())
    for symbol, span, enclosing, roles in occurrences:
        one = length_delimited(1, packed(*span)) + length_delimited(2, symbol.encode())
        one += tag(3, 0) + packed(roles)
        if enclosing:
            one += length_delimited(7, packed(*enclosing))
        body += length_delimited(2, one)
    for symbol, display in (names or {}).items():
        info = length_delimited(1, symbol.encode()) + length_delimited(6, display.encode())
        body += length_delimited(3, info)
    return length_delimited(2, body)


class ScipLocals(unittest.TestCase):
    """A `local N` symbol is unique within its document only. rust-analyzer
    starts the numbering afresh in every file, so two files' `local 0` are two
    unrelated bindings, and merging them attributes one file's name, definition
    and references to the other."""

    A = "consensus/src/a.rs"
    B = "consensus/src/b.rs"
    RUN = "rust-analyzer cargo c 1 a/run()."
    QUORUM = "rust-analyzer cargo c 1 a/quorum()."
    SOURCE_A = (
        "fn run() {\n"                  # 1  run spans 1-4
        "    let view = quorum();\n"    # 2  local 0 (view) defined, quorum called
        "    view;\n"                   # 3  local 0 referenced
        "}\n"                           # 4
        "fn quorum() {}\n"              # 5
    )
    SOURCE_B = (
        "fn other() {\n"                # 1
        "    let round = 1;\n"          # 2  local 0 (round) defined
        "    round;\n"                  # 3  local 0 referenced
        "}\n"                           # 4
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        (self.repo / "consensus/src").mkdir(parents=True)
        (self.repo / self.A).write_text(self.SOURCE_A)
        (self.repo / self.B).write_text(self.SOURCE_B)
        self.index = sl.index_path(self.sl_dir)
        self.write_index()
        sl.snapshot_write(self.repo, self.sl_dir, [self.A, self.B])
        self.saved = {n: getattr(sl, n) for n in ("repo_root", "say")}
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in self.saved.items()])
        self.loaded = sl.index_load(self.index)

    def write_index(self, run="run"):
        """Two documents that both define `local 0`; `run` names the function."""
        self.index.write_bytes(
            scip_document(
                "src/a.rs",
                [
                    (self.RUN, [0, 3, 6], [0, 0, 3, 1], 1),
                    ("local 0", [1, 8, 12], [1, 8, 12], 1),
                    (self.QUORUM, [1, 15, 21], None, 0),
                    ("local 0", [2, 4, 8], None, 0),
                    (self.QUORUM, [4, 3, 9], [4, 0, 4, 15], 1),
                ],
                {"local 0": "view", self.RUN: run, self.QUORUM: "quorum"},
            )
            + scip_document(
                "src/b.rs",
                [
                    ("local 0", [1, 8, 13], [1, 8, 13], 1),
                    ("local 0", [2, 4, 9], None, 0),
                ],
                {"local 0": "round"},
            )
        )

    def code(self, query, name):
        out = io.StringIO()
        args = argparse.Namespace(query=query, name=name, paths=[], tests=False, all=False)
        with contextlib.redirect_stdout(out):
            sl.cmd_code(args)
        return out.getvalue()

    def test_each_file_keeps_its_own_local(self):
        _occurrences, definitions, names = self.loaded
        locals_ = {sym: where for sym, where in definitions.items() if sl.index_is_local(sym)}
        self.assertEqual(
            locals_,
            {
                f"local 0 in {self.A}": (self.A, 2, 2),
                f"local 0 in {self.B}": (self.B, 2, 2),
            },
        )
        self.assertEqual(names[f"local 0 in {self.A}"], "view")
        self.assertEqual(names[f"local 0 in {self.B}"], "round")

    def test_a_locals_references_never_cross_into_another_file(self):
        out = self.code("refs", "view")
        self.assertIn("1 symbol(s) matching 'view'", out)
        self.assertIn(f"def  {self.A}:2", out)
        self.assertIn(f"ref  {self.A}:3", out)
        self.assertNotIn(self.B, out)
        other = self.code("refs", "round")
        self.assertIn("1 symbol(s) matching 'round'", other)
        self.assertNotIn(self.A, other)

    def test_a_local_is_named_in_its_file(self):
        out = self.code("defs", "round")
        self.assertIn(f"local 0 in {self.B} (round)", out)
        self.assertIn(f"{self.B}:2-2", out)

    def test_a_call_on_a_let_line_belongs_to_the_function(self):
        # The gap: the local's extent is its own binding on the `let` line, and
        # as the innermost definition containing the call it was reported as
        # the caller in place of the function.
        out = self.code("callers", "quorum")
        self.assertIn(f"{self.A}:2  in a/run()", out)
        self.assertNotIn("local", out)

    def test_a_local_is_not_matched_by_its_file_name(self):
        occurrences, definitions, names = self.loaded
        self.assertEqual(sl.index_match(occurrences, definitions, names, "src/b"), [])
        self.assertEqual(sl.index_match(occurrences, definitions, names, "local"), [])

    def test_locals_are_set_aside_when_a_global_carries_the_name(self):
        occurrences, definitions, names = self.loaded
        names = dict(names, **{self.RUN: "view"})
        found = sl.index_match(occurrences, definitions, names, "view")
        self.assertEqual(found, [self.RUN])
        self.assertEqual(sl.index_locals(names, "view", found), 1)
        self.assertEqual(sl.index_locals(names, "round", [f"local 0 in {self.B}"]), 0)

    def test_set_aside_locals_are_counted_in_the_listing(self):
        self.write_index(run="view")
        out = self.code("refs", "view")
        self.assertIn("1 symbol(s) matching 'view'", out)
        self.assertIn("a/run()", out)
        self.assertNotIn("local 0", out)
        self.assertIn("1 local variable(s) named 'view' not shown", out)

    def test_ast_scope_follows_the_files_that_mention_the_name(self):
        self.assertEqual(
            sl.ast_files(self.repo, self.sl_dir, "round", []), [pathlib.Path(self.B)]
        )


class IndexFreshness(unittest.TestCase):
    """A query must never present index coordinates as current ones, and must
    say when the tree has moved on -- including when it matches nothing."""

    REL = "consensus/src/x.rs"
    OUTER = "rust-analyzer cargo c 1 x/outer()."
    INNER = "rust-analyzer cargo c 1 x/inner()."
    SOURCE = (
        "fn outer() {\n"      # 1  outer spans 1-3
        "    inner();\n"      # 2  a call to inner
        "}\n"                 # 3
        "\n"                  # 4
        "fn inner() {}\n"     # 5  inner spans 5-5
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / "statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        self.file = self.repo / self.REL
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text(self.SOURCE)
        sl.index_path(self.sl_dir).write_bytes(
            scip_document(
                "src/x.rs",
                [
                    (self.OUTER, [0, 3, 8], [0, 0, 2, 1], 1),
                    (self.INNER, [1, 4, 9], None, 0),
                    (self.INNER, [4, 3, 8], [4, 0, 4, 13], 1),
                ],
            )
        )
        sl.snapshot_write(self.repo, self.sl_dir, [self.REL])
        self.saved = {n: getattr(sl, n) for n in ("repo_root", "say")}
        sl.repo_root = lambda: self.repo
        self.said = []
        sl.say = lambda message, *a, **k: self.said.append(str(message))
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in self.saved.items()])

    def code(self, query, name, **extra):
        out = io.StringIO()
        args = argparse.Namespace(
            query=query, name=name, paths=[], tests=False, all=False, **extra
        )
        with contextlib.redirect_stdout(out):
            code = sl.cmd_code(args)
        return code, out.getvalue(), "\n".join(self.said)

    def test_clean_tree_says_nothing(self):
        _code, _out, said = self.code("refs", "outer")
        self.assertNotIn("changed", said)

    def test_appending_a_function_warns_even_when_nothing_matches(self):
        # The gap: the warning was taken before any hit was placed, so a query
        # that matched nothing reported a clean tree.
        self.file.write_text(self.SOURCE + "\nfn appended() {}\n")
        code, out, said = self.code("refs", "appended")
        self.assertEqual(code, 1)
        self.assertIn("no symbol matches", out)
        self.assertIn("have changed since the index was built", said)

    def test_appending_warns_on_an_ordinary_listing_too(self):
        self.file.write_text(self.SOURCE + "\nfn appended() {}\n")
        _code, _out, said = self.code("refs", "outer")
        self.assertIn("have changed since the index was built", said)

    def test_callees_header_is_rebased(self):
        # The gap: the header printed the index extent verbatim.
        _code, before, _said = self.code("callees", "outer")
        self.assertIn(f"{self.REL}:1-3", before)
        self.file.write_text("// probe\n// probe\n" + self.SOURCE)
        _code, after, _said = self.code("callees", "outer")
        self.assertIn(f"{self.REL}:3-5", after)
        self.assertNotIn(f"{self.REL}:1-3", after)

    def test_a_lost_end_is_not_hidden_by_a_moved_start(self):
        # Prepend two lines so the start moves, and edit the closing brace so
        # the end cannot be mapped. Combining with `or` let `moved` win and
        # printed the stale end as though it were current.
        edited = "// probe\n// probe\n" + self.SOURCE.replace(
            "}\n\nfn inner", "} // touched\n\nfn inner", 1
        )
        self.file.write_text(edited)
        _code, out, _said = self.code("defs", "outer")
        self.assertIn("[lost]", out, out)
        self.assertNotIn("3-3  [moved]", out)
        _code, callees, _said = self.code("callees", "outer")
        self.assertIn("[lost]", callees, callees)

    def test_severity_puts_validity_first(self):
        self.assertEqual(sl.rebase_worst("moved", "lost"), "lost")
        self.assertEqual(sl.rebase_worst("unverified", "lost"), "lost")
        self.assertEqual(sl.rebase_worst("moved", "unverified"), "unverified")
        self.assertEqual(sl.rebase_worst("moved", ""), "moved")
        self.assertEqual(sl.rebase_worst("", ""), "")

    def test_an_unavailable_line_is_not_shown_as_a_number(self):
        self.assertEqual(sl.rebase_line(7, "lost"), "?(7)")
        self.assertEqual(sl.rebase_line(7, "unindexed"), "?(7)")
        self.assertEqual(sl.rebase_line(7, "moved"), "7")
        self.assertEqual(sl.rebase_line(7, ""), "7")

    def test_an_emptied_file_is_not_treated_as_unchanged(self):
        # The gap: the change test required the current text to be nonempty.
        self.file.write_text("")
        _code, out, said = self.code("refs", "outer")
        self.assertIn("lost", out)
        self.assertIn("have changed since the index was built", said)

    def test_a_deleted_file_is_reported(self):
        self.file.unlink()
        _code, out, said = self.code("refs", "outer")
        self.assertIn("lost", out)
        self.assertIn("gone or unreadable", said)

    def test_a_new_source_file_is_reported(self):
        (self.file.parent / "added.rs").write_text("fn fresh() {}\n")
        _code, _out, said = self.code("refs", "outer")
        self.assertIn("appeared since the index was built", said)

    def test_a_source_the_index_skipped_is_not_new(self):
        # storage keeps bench sources no module declares beside indexed code, and
        # calling them new told every query of a qmdb campaign to rebuild the index.
        skipped = self.file.parent / "bench.rs"
        skipped.write_text("fn bench() {}\n")
        built = sl.snapshot_path(self.sl_dir).stat().st_mtime
        os.utime(skipped, (built - 60, built - 60))
        _code, _out, said = self.code("refs", "outer")
        self.assertNotIn("appeared since the index was built", said)


class Ancestry(unittest.TestCase):
    """Anything before a `#[cfg(test)]` or a doc comment moves its item's start,
    so ancestry has to be real rather than an offset match or a node window."""

    @classmethod
    def setUpClass(cls):
        if not sl.ast_available():
            raise unittest.SkipTest("rust-analyzer is not installed")

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, text):
        path = self.tmp / "t.rs"
        path.write_text(text)
        return path

    def test_a_documented_test_module_is_found(self):
        self.write(
            "/// Documented test module.\n"      # 1
            "#[cfg(test)]\n"                     # 2
            "mod helpers {\n"                    # 3
            "    pub fn helper() {}\n"           # 4
            "}\n"                                # 5
            "pub fn production() {}\n"           # 6
        )
        self.assertEqual(sl.index_test_ranges(self.tmp, "t.rs"), [(1, 5)])
        self.assertTrue(sl.index_is_test(self.tmp, {}, "t.rs", 4))
        self.assertFalse(sl.index_is_test(self.tmp, {}, "t.rs", 6))

    def test_a_second_attribute_before_cfg_test(self):
        self.write(
            "#[allow(dead_code)]\n"              # 1
            "#[cfg(test)]\n"                     # 2
            "mod helpers {}\n"                   # 3
            "pub fn production() {}\n"           # 4
        )
        self.assertEqual(sl.index_test_ranges(self.tmp, "t.rs"), [(1, 3)])
        self.assertFalse(sl.index_is_test(self.tmp, {}, "t.rs", 4))

    def test_a_doc_comment_after_an_attribute_finds_its_item(self):
        path = self.write(
            "struct S { armed: bool }\n"                       # 1
            "impl S {\n"                                       # 2
            "    #[inline]\n"                                  # 3  the FN starts here
            "    /// Recover the state.\n"                     # 4
            "    fn recover(&mut self) { self.armed = true; }\n"  # 5
            "}\n"                                              # 6
        )
        found = sl.ast_notes(path, "Recover")
        self.assertEqual(len(found), 1, found)
        _line, _text, item = found[0]
        self.assertIsNotNone(item, "an earlier attribute must not hide the item")
        self.assertEqual(item[0], "FN")

    def test_a_comment_in_a_macro_body_has_no_item(self):
        path = self.write(
            "macro_rules! pick { ($($t:tt)*) => { $($t)* } }\n"  # 1
            "fn holder() {\n"                                    # 2
            "    pick! {\n"                                      # 3
            "        // never clear it twice\n"                  # 4
            "        let _ = 1;\n"                               # 5
            "    }\n"                                            # 6
            "}\n"                                                # 7
            "fn unrelated() {}\n"                                # 8
        )
        found = sl.ast_notes(path, "never clear")
        self.assertEqual(len(found), 1, found)
        _line, _text, item = found[0]
        self.assertIsNone(item, "must not reach past the macro to the next fn")

    def test_a_write_deep_in_a_macro_body_is_reported(self):
        body = "".join("        step();\n" for _ in range(90))
        path = self.write(
            "struct S { armed: bool }\n"
            "macro_rules! pick { ($($t:tt)*) => { $($t)* } }\n"
            "fn step() {}\n"
            "impl S {\n"
            "    fn wrapped(&mut self) {\n"
            "        pick! {\n" + body + "        self.armed = true;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        _writes, reads, _inits, opaque, _maybe = sl.ast_field_ops(path, "armed")
        self.assertEqual(len(opaque), 1, "the write far into the body must be seen")
        self.assertNotIn(opaque[0], reads)


class PromptPaths(unittest.TestCase):
    """Phase 2 runs the agent from the repository root, so prompt paths are
    relative to it, not to this subproject. The script lives two levels down,
    and a prompt that says `scripts/statelens.py` fails there."""

    REPO = HERE.parents[1]
    PROMPTS = sorted((HERE.parent / "prompts").rglob("*.md"))

    def test_there_are_prompts_to_check(self):
        self.assertTrue(self.PROMPTS, "no prompt files found")

    def test_script_is_named_from_the_repository_root(self):
        for path in self.PROMPTS:
            text = path.read_text()
            for line_number, line in enumerate(text.splitlines(), 1):
                if "scripts/statelens.py" not in line:
                    continue
                self.assertIn(
                    "statelens/scripts/statelens.py",
                    line,
                    f"{path.name}:{line_number} names the script relative to this "
                    f"subproject, but the agent runs from the repository root",
                )

    def test_referenced_subproject_files_exist(self):
        reference = __import__("re").compile(
            r"(?<![A-Za-z0-9_./-])statelens/[A-Za-z0-9_./-]+[A-Za-z0-9_/]"
        )
        for path in self.PROMPTS:
            for line_number, line in enumerate(path.read_text().splitlines(), 1):
                for found in reference.finditer(line):
                    target = self.REPO / found.group(0)
                    self.assertTrue(
                        target.exists(),
                        f"{path.name}:{line_number} refers to {found.group(0)}, "
                        f"which does not exist",
                    )


class AgentInvocation(unittest.TestCase):
    """A model or an effort that `config.env` sets has to reach the CLI. An option
    that is silently dropped looks exactly like one the CLI honoured, and the
    campaign would record a setting it never used."""

    def config(self, **values):
        base = {key: "" for key in sl.CONFIG_KEYS}
        base.update(values)
        return base

    def command(self, agent, phase=2, **values):
        return sl.agent_command(self.config(**values), agent, phase, pathlib.Path("/repo"))

    def test_an_empty_value_leaves_the_flag_out(self):
        for agent in ("claude", "codex"):
            command = self.command(agent)
            self.assertNotIn("--effort", command)
            self.assertNotIn("--model", command)
            self.assertFalse(
                [word for word in command if word.startswith("model_reasoning_effort")],
                f"{agent} must fall back to its own default",
            )

    def test_claude_takes_the_model_and_the_effort(self):
        command = self.command(
            "claude", STATELENS_CLAUDE_MODEL="claude-opus-5", STATELENS_CLAUDE_EFFORT="xhigh"
        )
        self.assertEqual(command[command.index("--model") + 1], "claude-opus-5")
        self.assertEqual(command[command.index("--effort") + 1], "xhigh")

    def test_codex_takes_the_effort_as_a_config_override(self):
        command = self.command("codex", STATELENS_CODEX_EFFORT="high")
        self.assertIn("model_reasoning_effort=high", command)
        self.assertEqual(command[command.index("model_reasoning_effort=high") - 1], "-c")

    def test_each_agent_reads_only_its_own_settings(self):
        command = self.command(
            "claude", STATELENS_CODEX_MODEL="gpt", STATELENS_CODEX_EFFORT="high"
        )
        self.assertNotIn("--model", command)
        self.assertNotIn("--effort", command)

    def test_the_effort_reaches_every_phase(self):
        for phase in (1, 2, "kb"):
            command = self.command("claude", phase, STATELENS_CLAUDE_EFFORT="max")
            self.assertIn("--effort", command, f"phase {phase} must carry the effort")

    def test_a_kb_extraction_reaches_the_corpus_only_through_the_kb_commands(self):
        command = self.command("claude", "kb")
        self.assertIn("Bash(python3 statelens/scripts/statelens.py kb:*)", command)
        self.assertNotIn("Bash(gh:*)", command)
        self.assertNotIn("--dangerously-skip-permissions", command)
        command = self.command("codex", "kb")
        self.assertIn("sandbox_workspace_write.network_access=false", command)


class TestGate(unittest.TestCase):
    """`just test` must run the campaign's own gate, for the profile the
    checkout was instrumented with, or a fix would be checked against other tests."""

    def test_the_campaign_and_the_recipe_share_one_command(self):
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.test_toolchain, campaign.profile_name = "stable", "marshal"
        self.assertEqual(campaign.test_command(), sl.gate_test_command("stable", "marshal"))

    def test_the_component_tests_are_the_simplex_tests_the_gate_leaves_out(self):
        # The gap: the gate excluded every `simplex::actors::` test, and nothing ran
        # them, so an instrumented tree that failed seven of them reported READY
        # without a word about it.
        for profile in ("simplex", "marshal"):
            command = sl.component_test_command("stable", profile)
            self.assertEqual(command[:3], ["cargo", "+stable", "nextest"])
            expression = command[-1]
            self.assertIn("test(/^simplex::/)", expression)
            self.assertIn("not test(/^simplex::tests::/)", expression)
            self.assertIn("not test(/^simplex::statelens::/)", expression)
            self.assertNotIn("marshal", expression)
        # qmdb gates every one of its tests, so nothing runs after the gate.
        self.assertIsNone(sl.component_test_command("stable", "qmdb"))

    def test_failed_tests_are_named_once_each(self):
        lines = [
            "        PASS [   0.010s] commonware-consensus simplex::actors::voter::ok",
            "        FAIL [   0.123s] commonware-consensus simplex::actors::voter::tests::a",
            "thread 'x' panicked at [statelens][INV-0012] replica=1 timeout",
            "        FAIL [   0.456s] commonware-consensus simplex::actors::batcher::b",
            "     TIMEOUT [  60.000s] commonware-consensus simplex::actors::resolver::c",
            "     SIGSEGV [   0.001s] commonware-consensus simplex::types::d",
            "     Summary [   3.000s] 4 tests run: 0 passed, 4 failed",
            "        FAIL [   0.123s] commonware-consensus simplex::actors::voter::tests::a",
            "        FAIL [   0.456s] commonware-consensus simplex::actors::batcher::b",
        ]
        self.assertEqual(
            sl.failed_tests(lines),
            [
                "simplex::actors::voter::tests::a",
                "simplex::actors::batcher::b",
                "simplex::actors::resolver::c",
                "simplex::types::d",
            ],
        )

    def test_failed_component_tests_are_reported_and_do_not_fail_the_campaign(self):
        campaign = sl.Campaign.__new__(sl.Campaign)
        with tempfile.TemporaryDirectory() as root:
            campaign.repo = campaign.dir = pathlib.Path(root)
            (campaign.dir / "logs").mkdir()
            campaign.test_toolchain, campaign.profile_name = "", "simplex"
            said = []
            saved = {name: getattr(sl, name) for name in ("run_logged", "say")}
            sl.say = lambda message, *a, **k: said.append(str(message))

            def run(command, log, cwd, stdin_text=None, echo=True):
                log.write_text(
                    "        FAIL [   0.1s] commonware-consensus simplex::actors::voter::t\n"
                )
                return 100, []

            sl.run_logged = run
            try:
                failed = campaign.component_tests()
            finally:
                for key, value in saved.items():
                    setattr(sl, key, value)
        self.assertEqual(failed, ["simplex::actors::voter::t"])
        self.assertTrue(any("not gated" in line for line in said), said)

    def test_each_profile_runs_its_own_filter(self):
        for profile, settings in sl.PROFILES.items():
            command = sl.gate_test_command("stable", profile)
            self.assertEqual(command[:3], ["cargo", "+stable", "nextest"])
            self.assertEqual(command[command.index("-p") + 1], f"commonware-{settings['crate']}")
            self.assertEqual(command[-1], settings["test_filter"])
        self.assertIn("marshal::", sl.gate_test_command("", "marshal")[-1])
        self.assertNotIn("marshal::", sl.gate_test_command("", "simplex")[-1])

    def test_the_profile_comes_from_the_campaign_in_the_checkout(self):
        with tempfile.TemporaryDirectory() as root:
            sl_dir = pathlib.Path(root)
            self.assertIsNone(sl.campaign_profile(sl_dir))
            (sl_dir / "campaign").mkdir()
            (sl_dir / "campaign" / "meta.json").write_text(json.dumps({"profile": "marshal"}))
            self.assertEqual(sl.campaign_profile(sl_dir), "marshal")


class CoverageSelection(unittest.TestCase):
    """`just coverage` takes the names `just fuzz` takes, so a marshal target must
    not be covered against the simplex profile's package, and a typo must name the
    targets that exist rather than silently covering all of them."""

    def select(self, *names, profile=None):
        return sl.coverage_selection(
            HERE.parents[1], argparse.Namespace(profile=profile, targets=list(names))
        )

    def test_no_name_covers_every_target_of_the_default_profile(self):
        profile, targets = self.select()
        self.assertEqual(profile, "simplex")
        self.assertEqual(targets, sl.profile_targets(HERE.parents[1], "simplex"))

    def test_a_profile_name_covers_that_profile(self):
        profile, targets = self.select("marshal")
        self.assertEqual(profile, "marshal")
        self.assertEqual(targets, sl.profile_targets(HERE.parents[1], "marshal"))

    def test_a_target_name_implies_its_profile(self):
        profile, targets = self.select("marshal_scenario_standard_inline_cert_mock_statelens")
        self.assertEqual(profile, "marshal")
        self.assertEqual(targets, ["marshal_scenario_standard_inline_cert_mock_statelens"])
        profile, targets = self.select("qmdb_verify_proof_statelens")
        self.assertEqual(profile, "qmdb")
        self.assertEqual(targets, ["qmdb_verify_proof_statelens"])

    def test_a_name_of_neither_profile_is_refused(self):
        with self.assertRaises(sl.Abort) as caught:
            self.select("nonsense")
        self.assertIn("not a profile", str(caught.exception))

    def test_a_target_the_profile_does_not_build_is_refused(self):
        with self.assertRaises(sl.Abort) as caught:
            self.select("simplex_does_not_exist")
        self.assertIn("builds no target", str(caught.exception))

    def test_the_report_is_scoped_to_what_the_profile_instruments(self):
        repo = HERE.parents[1]
        for profile in sl.PROFILES:
            sources, uninstrumented = sl.coverage_scope(repo, profile)
            self.assertEqual(
                sources,
                [str(repo / root.rstrip("/")) for root in sl.PROFILES[profile]["roots"]],
                "llvm-cov reads a trailing slash as a file and widens the report",
            )
            for source in sources:
                self.assertTrue(pathlib.Path(source).is_dir(), f"{source} must exist")
            self.assertEqual(uninstrumented, list(sl.PROFILES[profile]["warn"]))
            for path in uninstrumented:
                self.assertTrue(
                    any(str(repo / path).startswith(source) for source in sources),
                    f"{path} is left out of a report that does not cover it",
                )


class PlanClaims(unittest.TestCase):
    """A plan's Status is a coverage claim, and the first campaign that wrote one
    claimed `bound` for an invariant whose action is committed in a handler it never
    instrumented. The lint reads the claim against the section's own ledger and
    against the code."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.plan = self.dir / "plan.md"

    def write(self, body):
        self.plan.write_text("# StateLens instrumentation plan\n\n## Invariants\n\n" + body)
        return self.plan

    SITES = (
        "- Sites: `voter/state.rs` `State::construct_notarize`, signature - checked\n"
        "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
        "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
    )
    # What `subsystem_assertions` returns: (invariant, enclosing function) per site.
    CODE = {
        "consensus/src/simplex/actors/voter/state.rs": [
            ("INV-0016", "State::try_propose"),
            ("INV-0016", "State::construct_notarize"),
        ],
        "consensus/src/simplex/actors/voter/actor.rs": [],
    }
    EMPTY = {"consensus/src/simplex/actors/voter/state.rs": []}

    def test_a_bound_status_with_an_unchecked_commit_site_is_reported(self):
        path = self.write(
            "### INV-0016: A proposal rejected by certification is never built upon\n"
            "- Status: bound\n- Reading: pre and post\n"
            "- Sites:\n"
            "  - `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "  - `voter/actor.rs` `Actor::process_proposed`, relay - not checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("not checked" in problem for problem in problems),
            f"a bound status over an unchecked commit site must be reported: {problems}",
        )

    def test_the_same_ledger_is_accepted_for_a_partial_status(self):
        path = self.write(
            "### INV-0016: A proposal rejected by certification is never built upon\n"
            "- Status: partial\n- Reading: pre and post\n"
            "- Sites:\n"
            "  - `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "  - `voter/actor.rs` `Actor::process_proposed`, relay - not checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n"
            "- Notes: the relay is reached one iteration later\n"
        )
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])

    def test_a_claimed_binding_the_code_never_asserts_is_reported(self):
        path = self.write("### INV-0016: title\n- Status: bound\n- Reading: r\n" + self.SITES)
        problems = sl.lint_plan_file(path, ["INV-0016"], self.EMPTY)
        self.assertTrue(
            any("names it" in problem for problem in problems),
            f"a Status with no assertion in the code must be reported: {problems}",
        )

    def test_an_unbound_section_needs_only_a_status_and_a_reason(self):
        path = self.write("### INV-0016: title\n- Status: unbound\n- Notes: not reachable\n")
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.EMPTY), [])

    def test_an_unbound_section_the_code_asserts_is_reported(self):
        path = self.write("### INV-0016: title\n- Status: unbound\n- Notes: not reachable\n")
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("unbound, but the code asserts it" in problem for problem in problems),
            f"an unbound invariant with assertions must be reported: {problems}",
        )

    def test_a_site_called_checked_that_asserts_nothing_is_reported(self):
        path = self.write(
            "### INV-0016: A proposal rejected by certification is never built upon\n"
            "- Status: bound\n- Reading: pre and post\n"
            "- Sites:\n"
            "  - `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "  - `voter/actor.rs` `Actor::process_proposed`, the relay - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("calls `voter/actor.rs` checked" in problem for problem in problems),
            f"a ledger that certifies a site the code never asserts must be reported: {problems}",
        )

    def test_an_entry_wrapped_over_two_lines_keeps_its_not_checked(self):
        path = self.write(
            "### INV-0016: A proposal rejected by certification is never built upon\n"
            "- Status: partial\n- Reading: pre and post\n"
            "- Sites:\n"
            "  - `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "  - `voter/actor.rs` `Actor::process_proposed`, the relay of a local\n"
            "    proposal - not checked (the parent can be rejected while the build runs)\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n"
            "- Notes: the relay is reached one iteration later\n"
        )
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])

    def test_a_ledger_that_claims_coverage_without_naming_a_source_is_reported(self):
        for sites in ("- Sites: all of them, checked\n", "- Sites: checked\n"):
            path = self.write(
                "### INV-0016: title\n- Status: bound\n- Reading: r\n" + sites
                + "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
                "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
            )
            problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
            self.assertTrue(
                any("names no source" in problem for problem in problems),
                f"a ledger without a source must be reported: {sites!r} -> {problems}",
            )

    def test_an_entry_with_no_verdict_is_reported(self):
        for verdict in ("unchecked", "deferred", "no site available"):
            path = self.write(
                "### INV-0016: title\n- Status: bound\n- Reading: r\n"
                "- Sites:\n"
                "  - `voter/state.rs` `State::construct_notarize`, signature - checked\n"
                f"  - `voter/actor.rs` `Actor::process_proposed`, the relay - {verdict}\n"
                "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
                "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
            )
            problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
            self.assertTrue(
                any("neither `checked` nor `not checked`" in problem for problem in problems),
                f"an entry with no verdict must be reported: {verdict!r} -> {problems}",
            )

    def test_a_site_in_a_source_that_does_not_exist_is_reported(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/sate.rs` `State::construct_notarize`, signature - checked\n"
            "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("not an instrumented source" in problem for problem in problems),
            f"a ledger naming a source that does not exist must be reported: {problems}",
        )

    def test_a_ledger_written_as_one_bullet_per_site_keeps_every_site(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "- Sites: `voter/actor.rs` `Actor::process_proposed`, relay - not checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("not checked" in problem for problem in problems),
            f"a repeated field must extend the ledger, not replace it: {problems}",
        )
        self.assertEqual(sl.Campaign.commit_sites(path.read_text()), (2, 1))

    def test_an_assertion_elsewhere_in_the_file_does_not_certify_a_site(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/state.rs` `State::proposed`, the completion - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("elsewhere in that file" in problem for problem in problems),
            f"a dispatch assertion must not certify the commit site beside it: {problems}",
        )

    def test_a_site_named_without_its_type_is_read_like_a_qualified_one(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/state.rs` `try_propose`, dispatch - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])

    def test_a_checked_site_with_no_function_is_reported(self):
        path = self.write(
            "### INV-0016: title\n- Status: bound\n- Reading: r\n"
            "- Sites: `voter/state.rs`, the completion - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
        )
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("names no function" in problem for problem in problems),
            f"a checked entry must not fall back to file-only coverage: {problems}",
        )

    def test_a_fenced_block_inside_a_section_is_not_read_as_fields(self):
        body = (
            "### INV-0016: title\n- Status: partial\n- Reading: r\n"
            "- Sites: `voter/state.rs` `State::try_propose`, dispatch - checked\n"
            "- Assertions: `voter/state.rs` `State::try_propose`, `sl_implies!`\n"
            "- Probes: none\n- Ghost state: none\n"
            "- Edited lines: the match arm below\n\n"
            "```rust\n- Status: bound\n- Sites: nothing\n```\n\n"
            "- Notes: the fence is quoted code\n"
        )
        path = self.write(body)
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])
        self.assertEqual(sl.Campaign.parse_statuses(path.read_text()), {"INV-0016": "partial"})

    def test_a_bold_or_quoted_status_is_read_like_the_campaign_reads_it(self):
        path = self.write(
            "### INV-0016: title\n- **Status**: `bound`\n- Reading: r\n" + self.SITES
        )
        self.assertEqual(sl.lint_plan_file(path, ["INV-0016"], self.CODE), [])

    def test_a_missing_section_is_reported(self):
        path = self.write("### INV-0016: title\n- Status: bound\n- Reading: r\n" + self.SITES)
        problems = sl.lint_plan_file(path, ["INV-0016", "INV-0017"], self.CODE)
        self.assertTrue(
            any(problem.startswith("INV-0017: has no section") for problem in problems),
            f"an invariant with no section must be reported: {problems}",
        )

    def test_a_repeated_section_is_reported(self):
        body = "### INV-0016: title\n- Status: bound\n- Reading: r\n" + self.SITES
        path = self.write(body + "\n" + body)
        problems = sl.lint_plan_file(path, ["INV-0016"], self.CODE)
        self.assertTrue(
            any("more than one section" in problem for problem in problems),
            f"a repeated section must be reported: {problems}",
        )


class AssertionScanner(unittest.TestCase):
    """The ledger check reads assertions out of the code with a textual scan, which
    certified an assertion quoted in a block comment, and one in a `#[cfg(test)]`
    module sharing the production function's name, as production coverage."""

    PLAN = (
        "# Plan\n\n## Invariants\n\n### INV-0016: example\n"
        "- Status: bound\n- Reading: check dispatch\n"
        "- Sites: `actors/voter/state.rs` `State::try_propose`, dispatch - checked\n"
        "- Assertions: `actors/voter/state.rs` `State::try_propose`, `sl_assert!`\n"
        "- Probes: none\n- Ghost state: none\n- Edited lines: none\n- Notes: none\n"
    )
    TEST_MODULE = (
        "struct State;\n"
        "impl State { fn try_propose() {} }\n"
        "#[cfg(test)] mod tests {\n"
        '  fn try_propose() { sl_assert!(None, "INV-0016", true, "test only"); }\n'
        "}\n"
    )

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.source = self.root / "consensus/src/simplex/actors/voter/state.rs"
        self.source.parent.mkdir(parents=True)
        self.plan = self.root / "plan.md"
        self.plan.write_text(self.PLAN)

    def problems(self, code):
        self.source.write_text(code)
        return sl.lint_plan_file(self.plan, ["INV-0016"], sl.subsystem_assertions(self.root))

    def test_a_production_assertion_certifies_its_site(self):
        code = (
            "struct State;\nimpl State {\n"
            '    fn try_propose() { sl_assert!(None, "INV-0016", true, "checked"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_a_free_function_does_not_certify_a_method_claim(self):
        # The gap: a free function has no type, and that was taken for a match
        # with any type the ledger named; it is a different item.
        code = (
            "struct State;\nimpl State {\n    fn try_propose() {}\n}\n"
            'fn try_propose() { sl_assert!(None, "INV-0016", true, "free"); }\n'
        )
        self.assertTrue(self.problems(code), "a free function certified State::try_propose")
        # A bare ledger name is the less precise claim that a free function meets.
        self.plan.write_text(self.PLAN.replace("`State::try_propose`", "`try_propose`"))
        self.assertEqual(self.problems(code), [])

    def test_a_function_spelled_in_a_string_opens_nothing(self):
        # The gap: a string holding `fn try_propose() {}` was the last `fn` before
        # the site, so an assertion in another method was attributed to it.
        code = (
            "struct State;\nimpl State {\n    fn try_propose() {}\n"
            "    fn unrelated() {\n"
            '        let _example = r#"\nfn try_propose() {}\n"#;\n'
            '        sl_assert!(None, "INV-0016", true, "in unrelated");\n'
            "    }\n}\n"
        )
        self.assertTrue(self.problems(code), "a string's `fn` claimed the assertion")
        self.assertEqual(
            sl.subsystem_assertions(self.root)["consensus/src/simplex/actors/voter/state.rs"],
            [("INV-0016", "State::unrelated")],
        )

    def test_a_site_after_the_last_function_belongs_to_none(self):
        code = (
            "struct State;\nimpl State {\n    fn try_propose() {}\n}\n"
            "macro_rules! trailing {\n"
            '    () => { sl_assert!(None, "INV-0016", true, "after every body") };\n'
            "}\n"
        )
        self.assertTrue(self.problems(code), "a site outside every body certified a method")
        self.assertEqual(
            sl.subsystem_assertions(self.root)["consensus/src/simplex/actors/voter/state.rs"],
            [("INV-0016", None)],
        )

    def test_a_body_is_found_past_a_semicolon_in_the_signature(self):
        code = (
            "struct State;\nimpl State {\n"
            "    fn try_propose() -> [u8; 4] {\n"
            '        sl_assert!(None, "INV-0016", true, "checked");\n'
            "        [0; 4]\n    }\n"
            "    fn declared(&self) -> u8;\n"
            "}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_an_assertion_in_a_block_comment_certifies_nothing(self):
        problems = self.problems(
            "fn try_propose() {}\n"
            "/* Example only:\n"
            'sl_assert!(None, "INV-0016", true, "documentation");\n'
            "*/\n"
        )
        self.assertTrue(problems, "a comment after the function certified it")

    def test_an_assertion_in_a_line_comment_certifies_nothing(self):
        problems = self.problems(
            'fn try_propose() {\n    // sl_assert!(None, "INV-0016", true, "todo");\n}\n'
        )
        self.assertTrue(problems, "a commented-out assertion certified its function")

    def test_an_assertion_in_a_test_module_certifies_nothing(self):
        problems = self.problems(self.TEST_MODULE)
        self.assertTrue(problems, "a test function of the production name certified it")

    def test_a_test_module_on_one_line_is_found_without_the_tree(self):
        saved = sl.ast_available
        sl.ast_available = lambda: False
        self.addCleanup(setattr, sl, "ast_available", saved)
        problems = self.problems(self.TEST_MODULE)
        self.assertTrue(problems, "the fallback must see `#[cfg(test)] mod` on one line")
        commented = self.TEST_MODULE.replace("#[cfg(test)] mod tests {", "#[cfg(test)] // t\nmod tests {")
        self.assertTrue(self.problems(commented), "a comment after the attribute is not the item")

    def test_a_comment_after_code_certifies_nothing(self):
        problems = self.problems(
            "fn try_propose() {\n"
            '    let x = 1; // sl_assert!(None, "INV-0016", true, "trailing");\n'
            "}\n"
        )
        self.assertTrue(problems, "a trailing comment certified its function")

    def test_a_nested_block_comment_certifies_nothing(self):
        problems = self.problems(
            "fn try_propose() {}\n"
            "/* outer /* inner */\n"
            'sl_assert!(None, "INV-0016", true, "still a comment");\n'
            "*/\n"
        )
        self.assertTrue(problems, "a nested block comment certified its function")

    def test_a_comment_marker_in_a_string_is_text(self):
        code = (
            "struct State;\nimpl State {\n"
            "    fn try_propose() {\n"
            '        let url = "https://example.invalid/*";\n'
            '        sl_assert!(None, "INV-0016", true, "{url}");\n'
            "    }\n}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_blanking_keeps_every_line(self):
        text = 'a /* b\nc */ d // e\n"f // g" h\n'
        blanked = sl.blank_inert(text)
        self.assertEqual(blanked.count("\n"), text.count("\n"))
        self.assertEqual(blanked.splitlines()[2], '"f // g" h')
        self.assertNotIn("b", blanked.splitlines()[0])
        self.assertNotIn("e", blanked.splitlines()[1])
        self.assertEqual(sl.blank_inert(text, strings=True).splitlines()[2], "         h")

    def test_an_assertion_in_a_raw_string_certifies_nothing(self):
        problems = self.problems(
            "fn try_propose() {\n"
            '    let _example = r#"sl_assert!(None, "INV-0016", true, "example");"#;\n'
            "}\n"
        )
        self.assertTrue(problems, "a raw string certified its function")

    def test_a_method_of_another_type_certifies_nothing(self):
        # The gap: both `State::try_propose` and `Other::try_propose` reduced to the
        # bare name, so the other type's method certified the ledger's site.
        problems = self.problems(
            "struct State;\nimpl State {\n    fn try_propose() {}\n}\n"
            "struct Other;\nimpl Other {\n"
            '    fn try_propose() { sl_assert!(None, "INV-0016", true, "other"); }\n'
            "}\n"
        )
        self.assertTrue(problems, "Other::try_propose certified State::try_propose")

    def test_a_method_of_the_named_type_certifies_its_site(self):
        code = (
            "struct State;\n"
            "impl<S: Scheme> Elector<S> for State where S: Scheme {\n"
            '    fn try_propose() { sl_assert!(None, "INV-0016", true, "checked"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])
        self.assertEqual(
            sl.subsystem_assertions(self.root),
            {"consensus/src/simplex/actors/voter/state.rs": [("INV-0016", "State::try_propose")]},
        )

    def test_a_const_method_certifies_its_site(self):
        code = (
            "struct State;\nimpl State {\n"
            '    pub const fn try_propose() { sl_assert!(None, "INV-0016", true, "c"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_an_assertion_before_any_function_is_reported_not_a_crash(self):
        # The gap: a site with no `fn` before it had no function, and the ledger
        # comparison raised on it instead of refusing to certify.
        problems = self.problems(
            "macro_rules! helper {\n"
            '    () => { sl_assert!(None, "INV-0016", true, "in a macro body") };\n'
            "}\n"
            "struct State;\nimpl State { fn try_propose() { helper!(); } }\n"
        )
        self.assertTrue(problems, "a site in no function certified the ledger")

    def test_an_impl_trait_argument_is_not_an_impl_block(self):
        # rustfmt puts a tuple of `impl Trait` arguments one per line, so a line
        # starts with `impl`, exactly as a block header does.
        code = (
            "struct State;\n"
            "impl State {\n"
            "    fn try_propose(\n"
            "        net: (\n"
            "            impl Sender,\n"
            "            impl Receiver,\n"
            "        ),\n"
            '    ) { sl_assert!(None, "INV-0016", true, "checked"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])
        self.assertEqual(
            sl.subsystem_assertions(self.root),
            {"consensus/src/simplex/actors/voter/state.rs": [("INV-0016", "State::try_propose")]},
        )

    def test_a_string_continuation_keeps_the_scan_in_sync(self):
        literals = (
            '        let _a = "x \\\n y";\n'
            '        let _b = "{";\n'
            "        let _d = '\"';\n"
            "        let _e = '\\u{1F600}';\n"
        )
        other = (
            "struct State;\nimpl State { fn try_propose(&self) {} }\n"
            "struct Other;\nimpl Other {\n    fn try_propose(&self) {\n"
            + literals
            + '        sl_assert!(None, "INV-0016", true, "other");\n    }\n}\n'
        )
        self.assertTrue(self.problems(other), "a desynced scan certified Other's method")
        own = (
            "struct State;\nimpl State {\n    fn try_propose(&self) {\n"
            + literals
            + '        sl_assert!(None, "INV-0016", true, "checked");\n    }\n}\n'
        )
        self.assertEqual(self.problems(own), [])

    def test_two_types_of_one_name_need_the_path(self):
        code = (
            "mod immutable { pub struct Archive; }\nmod prunable { pub struct Archive; }\n"
            "trait Blocks { fn try_propose(&self); }\n"
            "impl Blocks for immutable::Archive {\n"
            '    fn try_propose(&self) { sl_assert!(None, "INV-0016", true, "immutable"); }\n'
            "}\n"
            "impl Blocks for prunable::Archive {\n"
            "    fn try_propose(&self) {}\n"
            "}\n"
        )
        self.source.write_text(code)
        found = sl.subsystem_assertions(self.root)["consensus/src/simplex/actors/voter/state.rs"]
        self.assertEqual(found, [("INV-0016", "immutable::Archive::try_propose")])
        tail = self.PLAN.replace("`State::try_propose`", "`Archive::try_propose`")
        self.plan.write_text(tail)
        self.assertEqual(sl.lint_plan_file(self.plan, ["INV-0016"], sl.subsystem_assertions(self.root)), [])
        self.plan.write_text(tail.replace("`Archive::try_propose`", "`prunable::Archive::try_propose`"))
        self.assertTrue(sl.lint_plan_file(self.plan, ["INV-0016"], sl.subsystem_assertions(self.root)))
        # With the method asserted under both types, the tail is ambiguous.
        self.source.write_text(code.replace("fn try_propose(&self) {}", 'fn try_propose(&self) { sl_assert!(None, "INV-0016", true, "prunable"); }'))
        self.plan.write_text(tail)
        problems = sl.lint_plan_file(self.plan, ["INV-0016"], sl.subsystem_assertions(self.root))
        self.assertTrue(any("more than one method" in problem for problem in problems), problems)

    def test_a_backticked_action_word_is_not_a_function_claim(self):
        # The gap: every backticked word of a ledger entry was a function claim, so
        # an action written as `notarize` matched a method of that name.
        self.plan.write_text(
            self.PLAN.replace(
                "- Sites: `actors/voter/state.rs` `State::try_propose`, dispatch - checked",
                "- Sites: `notarize` `actors/voter/state.rs` `State::try_propose` - checked",
            )
        )
        code = (
            "struct State;\nimpl State {\n    fn try_propose() {}\n"
            '    fn notarize() { sl_assert!(None, "INV-0016", true, "action"); }\n'
            "}\n"
        )
        self.assertTrue(self.problems(code), "an action word certified the method")

    def test_an_extern_function_is_a_function(self):
        code = (
            "struct State;\nimpl State {\n"
            '    extern "C" fn try_propose() { sl_assert!(None, "INV-0016", true, "c"); }\n'
            "}\n"
        )
        self.assertEqual(self.problems(code), [])

    def test_impl_types_and_function_matching(self):
        self.assertFalse(sl.function_matches(None, "State::f"))
        self.assertEqual(sl.impl_type("<S: Scheme> Round<S> "), "Round")
        self.assertEqual(sl.impl_type("<S> Elector<S> for RoundRobin<S> where S: Scheme "), "RoundRobin")
        self.assertEqual(sl.impl_type(" crate::marshal::Actor<E, S> "), "crate::marshal::Actor")
        self.assertEqual(sl.impl_type(" Blocks for prunable::Archive<E> "), "prunable::Archive")
        # A claim may give the type's path or its tail; the tail of another path is
        # not it.
        self.assertTrue(sl.function_matches("prunable::Archive::f", "Archive::f"))
        self.assertTrue(sl.function_matches("prunable::Archive::f", "prunable::Archive::f"))
        self.assertFalse(sl.function_matches("prunable::Archive::f", "immutable::Archive::f"))
        self.assertFalse(sl.function_matches("State::f", "a::State::f"))
        self.assertTrue(sl.function_matches("State::f", "State::f"))
        self.assertFalse(sl.function_matches("Other::f", "State::f"))
        # A qualified claim names a method; a free function is a different item. A
        # bare claim is met by any function or method of the name.
        self.assertFalse(sl.function_matches("f", "State::f"))
        self.assertTrue(sl.function_matches("State::f", "f"))
        self.assertTrue(sl.function_matches("f", "f"))
        self.assertFalse(sl.function_matches("State::g", "f"))


class RepairRevalidation(unittest.TestCase):
    """A repair may remove the assertion a plan certifies, and the campaign kept the
    plan verdict taken before the repair: a buildable, passing tree handed over with
    a stale clean audit."""

    ORIGINAL = (
        "struct State;\nimpl State {\n"
        "    fn try_propose(required: bool) {\n"
        '        sl_assert!(None, "INV-0016", required, "checked");\n'
        "    }\n}\n"
    )

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.source = self.root / "consensus/src/simplex/actors/voter/state.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(self.ORIGINAL)
        self.helper = self.root / "consensus/src/simplex/statelens.rs"
        self.helper.write_text("pub fn evidence() -> bool { true }\n")
        self.plan = self.root / "plan.md"
        self.plan.write_text(AssertionScanner.PLAN)
        self.campaign = sl.Campaign.__new__(sl.Campaign)
        self.campaign.repo = self.campaign.dir = self.root
        self.campaign.profile = sl.PROFILES["simplex"]
        self.campaign.invariants = [("simplex", pathlib.Path("INV-0016.md"))]
        self.campaign.repair_prompt = lambda *_args: "fixture repair"
        self.campaign.check_scope = lambda: None
        self.campaign.record = lambda: None
        self.saved_say = sl.say
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(setattr, sl, "say", self.saved_say)
        # The audit's verdict stands for the tree at the first plan lint.
        self.campaign.check_plan()
        self.assertEqual(self.campaign.plan_problems, 0)
        self.assertIsNotNone(self.campaign.audit_content)

    def build(self, repair, failures=1):
        outcomes = iter([("compiler", ["fixture diagnostic"])] * failures + [None])
        self.campaign.build_once = lambda _attempt: next(outcomes)
        self.campaign.agent_step = lambda *_args: repair()
        self.campaign.build()

    def test_a_repair_that_removes_the_assertion_is_linted(self):
        self.build(
            lambda: self.source.write_text(
                "struct State;\nimpl State { fn try_propose(required: bool) {} }\n"
            )
        )
        self.assertGreater(self.campaign.plan_problems, 0, "the old clean verdict survived")
        self.assertEqual(self.campaign.stale, ["consensus/src/simplex/actors/voter/state.rs"])

    def test_a_repair_that_keeps_the_assertion_stays_clean(self):
        self.build(lambda: None)
        self.assertEqual(self.campaign.plan_problems, 0)
        self.assertEqual(self.campaign.stale, [])

    def test_a_repair_that_rewrites_the_condition_makes_the_audit_stale(self):
        # The gap: the lint sees the id, the site and the function, all unchanged,
        # and passes; only the digest of the audited tree can say the audit is stale.
        self.build(lambda: self.source.write_text(self.ORIGINAL.replace(", required,", ", true,")))
        self.assertEqual(self.campaign.plan_problems, 0, "the lint cannot see this change")
        self.assertEqual(self.campaign.stale, ["consensus/src/simplex/actors/voter/state.rs"])

    def test_a_repair_to_a_helper_or_the_plan_makes_the_audit_stale(self):
        def repair():
            self.helper.write_text("pub fn evidence() -> bool { false }\n")
            self.plan.write_text(self.plan.read_text().replace("Notes: none", "Notes: weakened"))

        self.build(repair)
        self.assertEqual(self.campaign.stale, ["consensus/src/simplex/statelens.rs", "plan.md"])

    def test_the_summary_the_script_appends_does_not_count_as_a_change(self):
        self.plan.write_text(self.plan.read_text() + "\n## Summary\n\n- Invariants: 1\n")
        self.build(lambda: None)
        self.assertEqual(self.campaign.stale, [])

    def test_a_build_without_repair_leaves_the_audit_current(self):
        self.build(lambda: self.fail("no repair is run"), failures=0)
        self.assertIsNone(self.campaign.stale)

    def test_a_build_that_never_succeeds_still_marks_the_audit_stale(self):
        # The summary a failed build leaves behind is read before the checkout is
        # fixed by hand and fuzzed with --skip-campaign, so it must not certify
        # the tree the repairs replaced.
        with self.assertRaises(sl.Abort):
            self.build(
                lambda: self.source.write_text(self.ORIGINAL.replace(", required,", ", true,")),
                failures=sl.REPAIR_ATTEMPTS + 1,
            )
        self.assertEqual(self.campaign.stale, ["consensus/src/simplex/actors/voter/state.rs"])

    def test_the_plan_summary_records_a_stale_audit(self):
        run = lambda *args: subprocess.run(  # noqa: E731
            ("git",) + args, cwd=self.root, capture_output=True, text=True, check=True
        )
        run("init", "-q", ".")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        run("config", "commit.gpgsign", "false")
        run("add", "-A")
        run("commit", "-qm", "base")
        del self.campaign.record  # the real method, over the stub of setUp
        self.campaign.stale = ["consensus/src/simplex/actors/voter/state.rs"]
        self.campaign.record()
        summary = self.plan.read_text().split("## Summary", 1)[1]
        self.assertIn(
            "- Audit: stale; a repair changed 1 validated file(s) after it: "
            "consensus/src/simplex/actors/voter/state.rs",
            summary,
        )
        self.campaign.stale = []
        self.campaign.record()
        self.assertNotIn("Audit", self.plan.read_text().split("## Summary", 1)[1])

    def test_a_later_lint_does_not_move_the_validated_content(self):
        self.source.write_text(self.ORIGINAL.replace(", required,", ", true,"))
        self.campaign.check_plan()
        self.assertEqual(
            self.campaign.changed_since_validation(),
            ["consensus/src/simplex/actors/voter/state.rs"],
            "a clean lint must not re-validate the tree",
        )

    def summary(self, **values):
        campaign = sl.Campaign.__new__(sl.Campaign)
        fields = dict(
            repo=self.root, base=None, agent="claude", profile_name="simplex",
            profile=sl.PROFILES["simplex"], targets=[], fuzz_toolchain="nightly",
            statuses={"INV-0016": "bound"}, inactive=[], audited=[],
            coverage=(3, 1), plan_problems=0, sites=None, components=None,
            stale=None, reason=None, panic=None, initialized=False, dir=self.root,
        )
        fields.update(values)
        for key, value in fields.items():
            setattr(campaign, key, value)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            campaign.finish(0, "READY")
        return out.getvalue()

    def test_lint_problems_mark_the_coverage_unvalidated(self):
        text = self.summary(plan_problems=2)
        self.assertIn("coverage   UNVALIDATED: 2 plan lint problem(s)", text)
        self.assertIn("result     READY", text)
        self.assertNotIn("UNVALIDATED", self.summary())

    def test_a_stale_audit_marks_the_coverage_unvalidated_despite_a_clean_lint(self):
        text = self.summary(audited=[], stale=["consensus/src/simplex/actors/voter/state.rs"])
        self.assertIn("audit      no status change [stale: a repair changed the tree after it]", text)
        self.assertIn(
            "coverage   UNVALIDATED: a repair changed 1 validated file(s) after the audit "
            "(consensus/src/simplex/actors/voter/state.rs)",
            text,
        )
        self.assertIn("result     READY", text)
        both = self.summary(plan_problems=1, stale=["plan.md"])
        self.assertIn("1 plan lint problem(s), so the code does not support", both)
        self.assertIn("; a repair changed 1 validated file(s)", both)
        self.assertNotIn("stale", self.summary(audited=[], stale=[]))

    def test_failed_component_tests_are_named_beside_the_result(self):
        text = self.summary(components=["simplex::actors::voter::t"])
        self.assertIn("components 1 failed, not gated: simplex::actors::voter::t", text)
        self.assertIn("components all passed", self.summary(components=[]))
        self.assertNotIn("components", self.summary(components=None))

    def test_inactive_bindings_are_named_beside_the_statuses(self):
        text = self.summary(inactive=["INV-0007"])
        self.assertIn("unbound 0); inactive in the fuzz targets: INV-0007", text)

    def test_no_audit_marks_the_coverage_unvalidated(self):
        text = self.summary(audited=None)
        self.assertNotIn("statelens: audit", text)
        self.assertIn("coverage   UNVALIDATED: no audit pass ran (STATELENS_AUDIT=0)", text)
        self.assertNotIn("UNVALIDATED", self.summary(audited=None, statuses={}))


class PhaseOrder(unittest.TestCase):
    """The audit is the last agent pass, so its verdict stands for the tree the plan
    lint fingerprints and the build hands over. Before, the beacon agents ran after
    it and could rewrite an assertion the audit had endorsed, unseen by anything."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.source = self.root / "consensus/src/simplex/actors/voter/state.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(RepairRevalidation.ORIGINAL)
        (self.root / "plan.md").write_text(AssertionScanner.PLAN)
        self.campaign = sl.Campaign.__new__(sl.Campaign)
        fields = dict(
            repo=self.root, dir=self.root, base=None, agent="fixture",
            profile_name="simplex", profile=sl.PROFILES["simplex"], targets=[],
            fuzz_toolchain="nightly", invariants=[("simplex", pathlib.Path("INV-0016.md"))],
            config={"STATELENS_AUDIT": "1"}, statuses={"INV-0016": "bound"}, inactive=[],
            audited=None, coverage=None, plan_problems=None, sites=None, components=None,
            reason=None, panic=None, initialized=False,
        )
        for key, value in fields.items():
            setattr(self.campaign, key, value)
        self.campaign.invariant_prompts = lambda: []
        self.campaign.beacon_prompts = lambda: [("beacons", "fixture beacons")]
        self.campaign.audit_prompts = lambda: [("audit", "fixture audit")]
        self.campaign.check_scope = lambda: None
        self.campaign.record = lambda: None
        self.campaign.build_once = lambda _attempt: None
        self.steps, self.audited = [], []
        saved = sl.say
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(setattr, sl, "say", saved)

    def handover(self, beacon_edit=None, audit_edit=None):
        def agent_step(name, _prompt):
            self.steps.append(name)
            if name == "beacons" and beacon_edit:
                self.source.write_text(beacon_edit)
            if name == "audit":
                if audit_edit:
                    self.source.write_text(audit_edit)
                self.audited.append(sl.sha256(self.source))

        self.campaign.agent_step = agent_step
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.campaign.instrument()
            self.campaign.build()
            self.campaign.finish(0, "READY")
        return out.getvalue()

    def test_the_audit_runs_after_the_beacon_step(self):
        self.handover()
        self.assertEqual(self.steps, ["beacons", "audit"])

    def test_an_assertion_the_beacon_agent_rewrote_is_audited_as_handed_over(self):
        weakened = RepairRevalidation.ORIGINAL.replace(", required,", ", true,")
        out = self.handover(weakened)
        self.assertEqual(self.audited, [sl.sha256(self.source)], "the audit must see the final tree")
        self.assertEqual(self.campaign.plan_problems, 0)
        self.assertIsNotNone(self.campaign.audit_content, "the fingerprint follows the audit")
        self.assertNotIn("UNVALIDATED", out)
        self.assertIn("result     READY", out)

    def test_the_fingerprint_is_of_the_tree_the_audit_left(self):
        # The audit's own edits are what the build validates, so the fingerprint
        # must be taken after them, and a first-attempt build hands them over
        # with nothing stale.
        edited = RepairRevalidation.ORIGINAL.replace('"checked"', '"audited"')
        out = self.handover(audit_edit=edited)
        self.assertEqual(
            self.campaign.audit_content["consensus/src/simplex/actors/voter/state.rs"],
            sl.sha256(self.source),
        )
        self.assertIsNone(self.campaign.stale)
        self.assertNotIn("UNVALIDATED", out)

    def test_without_an_audit_the_statuses_are_reported_unvalidated(self):
        self.campaign.config = {"STATELENS_AUDIT": "0"}
        out = self.handover()
        self.assertEqual(self.steps, ["beacons"])
        self.assertIn("coverage   UNVALIDATED: no audit pass ran (STATELENS_AUDIT=0)", out)
        self.assertIn("result     READY", out)


class InactiveBindings(unittest.TestCase):
    """A binding can be complete and still never evaluated by the fuzz targets,
    whose `cert_mock` scheme hides what its `pre` needs; the Status qualifier says so
    and the campaign reports it apart from the statuses."""

    PLAN = (
        "# Plan\n\n## Invariants\n\n### INV-0007: title\n"
        "- Status: partial (inactive in the fuzz targets)\n- Reading: r\n"
        "- Sites: `voter/state.rs` `State::construct_notarize`, signature - checked\n"
        "- Assertions: `voter/state.rs` `State::construct_notarize`, `sl_implies!`\n"
        "- Probes: none\n- Ghost state: none\n- Edited lines: none\n"
        "- Notes: the mock certificate is an opaque handle\n"
    )
    CODE = {"consensus/src/simplex/actors/voter/state.rs": [("INV-0007", "State::construct_notarize")]}

    def test_the_qualifier_lints_as_its_status(self):
        with tempfile.TemporaryDirectory() as root:
            plan = pathlib.Path(root) / "plan.md"
            plan.write_text(self.PLAN)
            self.assertEqual(sl.lint_plan_file(plan, ["INV-0007"], self.CODE), [])
        self.assertEqual(sl.Campaign.parse_statuses(self.PLAN), {"INV-0007": "partial"})
        self.assertEqual(sl.Campaign.inactive_invariants(self.PLAN), ["INV-0007"])

    def test_a_plain_status_is_active(self):
        plain = self.PLAN.replace(" (inactive in the fuzz targets)", "")
        self.assertEqual(sl.Campaign.inactive_invariants(plain), [])
        self.assertEqual(sl.inactive_note([]), "")
        self.assertEqual(sl.inactive_note(["INV-0007"]), "; inactive in the fuzz targets: INV-0007")

    def test_a_paraphrased_qualifier_is_reported_not_dropped(self):
        # The gap: `partial (not active under cert_mock)` passed the lint and was
        # counted as an active partial binding.
        paraphrased = self.PLAN.replace(
            "(inactive in the fuzz targets)", "(not active under cert_mock)"
        )
        with tempfile.TemporaryDirectory() as root:
            plan = pathlib.Path(root) / "plan.md"
            plan.write_text(paraphrased)
            problems = sl.lint_plan_file(plan, ["INV-0007"], self.CODE)
        self.assertTrue(any("qualifier" in problem for problem in problems), problems)
        self.assertEqual(sl.Campaign.inactive_invariants(paraphrased), [])


class KbSnippets(unittest.TestCase):
    """`kb grep` confines a match to the sections the registry allows, but the
    snippet around it was cut from the whole file, so a match on a section's last
    line showed the heading of the section the search excluded."""

    BODY = (
        "# Finding\n"             # 1
        "\n"                      # 2
        "## Root Cause\n"         # 3
        "needle\n"                # 4
        "## Excluded sentinel\n"  # 5
        "excluded body\n"         # 6
        "## Context\n"            # 7
        "more\n"                  # 8
    )

    def setUp(self):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "f.md").write_text(self.BODY)
        spans = sl.section_spans(self.BODY)
        self.entry = {
            "kind": "finding", "order": 0, "root": str(root), "path": "f.md",
            "identifier": "f", "modules": ["consensus/simplex"],
            "sections": {k: v for k, v in spans.items() if k in sl.KB_STATE_SECTIONS},
            "refs": {"paths": [], "symbols": []},
        }

    def hit(self, needle):
        hits = sl.kb_grep([self.entry], "simplex", needle)
        self.assertEqual(len(hits), 1, hits)
        _order, _path, _offset, entry, section, line = hits[0]
        return section, line, sl.kb_snippet(entry, line)

    def test_a_hit_on_a_sections_last_line_shows_no_excluded_heading(self):
        section, line, snippet = self.hit("needle")
        self.assertEqual((section, line), ("Root Cause", 4))
        self.assertIn("needle", snippet)
        self.assertNotIn("Excluded sentinel", snippet)

    def test_a_hit_on_a_sections_first_line_shows_no_excluded_body(self):
        section, line, snippet = self.hit("more")
        self.assertEqual((section, line), ("Context", 8))
        self.assertIn("more", snippet)
        self.assertNotIn("excluded body", snippet)
        # With more context the window reaches two lines back, into the excluded
        # section, unless it is clamped.
        wider = sl.kb_snippet(self.entry, line, context=5)
        self.assertIn("more", wider)
        self.assertNotIn("excluded body", wider)
        self.assertNotIn("Excluded sentinel", wider)

    def test_an_excluded_section_is_not_searched(self):
        self.assertEqual(sl.kb_grep([self.entry], "simplex", "excluded"), [])

    def test_a_document_keeps_the_whole_file_context(self):
        document = dict(self.entry, kind="document", sections={}, modules=[])
        snippet = sl.kb_snippet(document, 4)
        self.assertIn("Root Cause", snippet)
        self.assertIn("Excluded sentinel", snippet)


class LineCitations(unittest.TestCase):
    """A line number means something only at one commit: an invariant cites lines as
    `path:line@commit` (lint rule 10), and ends with the cited lines copied in at that
    commit (rule 11), which `statelens.py excerpts` writes."""

    SOURCE = (
        "//! First line\n"                       # 1
        "//! Second, with a dash — here\n"  # 2  non-ASCII, escaped in an excerpt
        "//! see line 5 of the table\n"          # 3  prose a bare-line check must not read
        "/// ```rust\n"                          # 4  a fence inside the excerpt
        "/// code\n"                             # 5
        "/// ```\n"                              # 6
        "fn main() {}\n"                         # 7
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        source = self.repo / "consensus/src/x.rs"
        source.parent.mkdir(parents=True)
        source.write_text(self.SOURCE)
        self.registry = self.repo / "statelens/invariants/simplex"
        self.registry.mkdir(parents=True)
        for args in (("init", "-q", "."), ("config", "user.email", "t@example.invalid"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false"),
                     ("add", "-A"), ("commit", "-qm", "base")):
            subprocess.run(("git",) + args, cwd=self.repo, capture_output=True, check=True)
        self.commit = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"], cwd=self.repo,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        sl._GIT_FILES.clear()

    def invariant(self, evidence, name="INV-0001.md"):
        path = self.registry / name
        path.write_text(
            "---\nid: INV-0001\ntitle: t\nsource_kind: comment\n"
            f"source_ref: consensus/src/x.rs:1@{self.commit}\nscope: [replica]\n---\n\n"
            "## Statement\nThe replica shall hold.\n\n## Rationale\nBecause.\n\n"
            f"## Evidence\n{evidence}\n"
        )
        return path

    def rule(self, path, number):
        return [problem for problem in sl.lint_file(path) if f"(rule {number})" in problem]

    def test_a_line_without_a_commit_is_reported(self):
        path = self.invariant("`consensus/src/x.rs:3` says so.")
        self.assertTrue(any("without a commit" in p for p in self.rule(path, 10)))

    def test_a_pinned_line_that_resolves_needs_only_its_excerpt(self):
        path = self.invariant(f"`consensus/src/x.rs:3-6@{self.commit}` says so.")
        self.assertEqual(self.rule(path, 10), [])
        self.assertTrue(self.rule(path, 11), "a pinned citation needs its excerpt")
        path.write_text(sl.with_excerpts(path.read_text(), self.repo))
        self.assertEqual(sl.lint_file(path), [])

    def test_a_citation_that_does_not_resolve_is_reported(self):
        path = self.invariant(
            f"`x.rs:3@{self.commit}` and `consensus/src/x.rs:99@{self.commit}` say so."
        )
        problems = self.rule(path, 10)
        self.assertTrue(any("no file x.rs exists" in p for p in problems), problems)
        self.assertTrue(any("has 7 lines there" in p for p in problems), problems)

    def test_bare_lines_and_branch_links_are_reported(self):
        path = self.invariant(
            "It says so (lines 3-4), in https://github.com/o/r/blob/main/x.rs#L3, unlike "
            f"https://github.com/o/r/blob/{self.commit}/x.rs#L3 and https://example.invalid:443/."
        )
        problems = self.rule(path, 10)
        self.assertEqual(len(problems), 2, problems)
        self.assertTrue(any("`lines 3`" in p for p in problems))
        self.assertTrue(any("a line of a branch" in p for p in problems))

    def test_an_excerpt_merges_near_ranges_escapes_and_fences(self):
        text = self.invariant(
            f"`consensus/src/x.rs:3-6@{self.commit}` says so."
        ).read_text()
        section = sl.excerpt_section(text, self.repo)
        # source_ref cites line 1 and the text 3-6: one line apart, so one excerpt.
        self.assertIn(f"`consensus/src/x.rs:1-6@{self.commit}`\n````rust\n", section)
        self.assertIn("//! Second, with a dash \\u2014 here", section)
        self.assertIn("/// ```\n````", section, "the fence outgrows the one inside")
        self.assertTrue(section.isascii())

    def test_the_excerpt_section_is_not_read_as_citations(self):
        path = self.invariant(f"`consensus/src/x.rs:3@{self.commit}` says so.")
        path.write_text(sl.with_excerpts(path.read_text(), self.repo))
        self.assertIn("see line 5 of the table", path.read_text())
        self.assertEqual(sl.lint_file(path), [], "prose inside an excerpt is not a bare line")
        self.assertEqual(sl.with_excerpts(path.read_text(), self.repo), path.read_text())

    def test_a_stale_excerpt_is_reported_and_rewritten(self):
        path = self.invariant(f"`consensus/src/x.rs:3@{self.commit}` says so.")
        path.write_text(sl.with_excerpts(path.read_text(), self.repo).replace("code", "edited"))
        self.assertTrue(self.rule(path, 11))
        saved = (sl.repo_root, sl.say)
        sl.repo_root, sl.say = (lambda: self.repo), (lambda *_a, **_k: None)
        self.addCleanup(lambda: (setattr(sl, "repo_root", saved[0]), setattr(sl, "say", saved[1])))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sl.cmd_excerpts(argparse.Namespace(paths=[str(path)], check=True)), 3)
            self.assertEqual(sl.cmd_excerpts(argparse.Namespace(paths=[str(path)], check=False)), 0)
            self.assertEqual(sl.cmd_excerpts(argparse.Namespace(paths=[str(path)], check=True)), 0)
        self.assertEqual(sl.lint_file(path), [])

    def test_a_file_without_pinned_citations_gets_no_section(self):
        path = self.invariant("Human-authored.")
        path.write_text(path.read_text().replace(f"consensus/src/x.rs:1@{self.commit}", "x"))
        self.assertEqual(sl.lint_file(path), [])
        self.assertNotIn(sl.EXCERPTS, sl.with_excerpts(path.read_text(), self.repo))

    def test_outside_a_clone_citations_are_not_resolved(self):
        elsewhere = pathlib.Path(tempfile.mkdtemp()) / "invariants/simplex"
        self.addCleanup(shutil.rmtree, elsewhere.parent.parent, True)
        elsewhere.mkdir(parents=True)
        path = self.invariant(f"`consensus/src/x.rs:99@{self.commit}` says so.")
        moved = elsewhere / "INV-0001.md"
        moved.write_text(path.read_text())
        self.assertEqual(self.rule(moved, 10) + self.rule(moved, 11), [])

    def test_extraction_pins_head_and_names_tracked_changes(self):
        values = sl.extract_values(
            self.repo, HERE.parent, "comment", "simplex", ["consensus/src/x.rs"]
        )
        self.assertEqual(values["COMMIT"], self.commit)
        (self.repo / "consensus/src/x.rs").write_text(self.SOURCE + "// edited\n")
        (self.repo / "consensus/src/new.rs").write_text("// untracked\n")
        (self.registry / "INV-0002.md").write_text("draft\n")
        self.assertEqual(sl.unpinnable(sl.worktree_state(self.repo)), ["consensus/src/x.rs"])


class ConfigLayers(unittest.TestCase):
    """`config.env` is tracked, so a knowledge-base root or any private value goes
    in `config.local.env`, which git ignores and which overrides the tracked file;
    the environment overrides both."""

    def setUp(self):
        self.sl_dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.sl_dir, True)
        (self.sl_dir / "config.env").write_text(
            "# defaults\nSTATELENS_AGENT=claude\nSTATELENS_KB=\nSTATELENS_AUDIT=1\n"
        )
        saved = os.environ.pop("STATELENS_KB", None)
        self.addCleanup(lambda: os.environ.update({"STATELENS_KB": saved}) if saved else None)

    def test_the_tracked_file_alone_gives_the_defaults(self):
        values = sl.load_config(self.sl_dir)
        self.assertEqual((values["STATELENS_AGENT"], values["STATELENS_KB"]), ("claude", ""))

    def test_the_local_file_overrides_the_tracked_one(self):
        (self.sl_dir / sl.CONFIG_LOCAL).write_text("STATELENS_KB=/private/findings\n")
        values = sl.load_config(self.sl_dir)
        self.assertEqual(values["STATELENS_KB"], "/private/findings")
        self.assertEqual(values["STATELENS_AGENT"], "claude", "untouched keys keep the default")

    def test_the_environment_overrides_both(self):
        (self.sl_dir / sl.CONFIG_LOCAL).write_text("STATELENS_KB=/private/findings\n")
        os.environ["STATELENS_KB"] = "/other"
        try:
            self.assertEqual(sl.load_config(self.sl_dir)["STATELENS_KB"], "/other")
        finally:
            del os.environ["STATELENS_KB"]

    def test_a_malformed_local_line_names_its_file(self):
        (self.sl_dir / sl.CONFIG_LOCAL).write_text("no equals sign\n")
        with self.assertRaises(sl.Abort) as caught:
            sl.load_config(self.sl_dir)
        self.assertIn("config.local.env:1", str(caught.exception))

    def test_the_local_file_is_ignored_by_git(self):
        ignored = (HERE.parent / ".gitignore").read_text().splitlines()
        self.assertIn(sl.CONFIG_LOCAL, ignored)
        tracked = (HERE.parent / "config.env").read_text().splitlines()
        self.assertIn("STATELENS_KB=", tracked, "the tracked file must leave the corpus root empty")


class AuditBatches(unittest.TestCase):
    """The audit runs one agent per batch, and each batch's verdict stands for the
    tree it left. A later batch that changes or removes a line may have edited what
    an earlier binding rests on, which nothing reviews again, so those bindings are
    reported unreviewed; a batch that only adds lines changes nothing reviewed."""

    SOURCE = (
        "struct State;\nimpl State {\n"
        "    fn try_propose(required: bool) {\n"
        '        sl_assert!(None, "INV-0016", evidence(required), "a");\n'
        "    }\n"
        "    fn try_other(required: bool) {\n"
        '        sl_assert!(None, "INV-0017", evidence(required), "b");\n'
        "    }\n}\n"
    )
    HELPER = "pub fn evidence(required: bool) -> bool {\n    required\n}\n"
    FIRST = "## Task: audit the bindings of invariants INV-0016 of the simplex registry\n"
    SECOND = "## Task: audit the bindings of invariants INV-0017 of the simplex registry\n"

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.source = self.root / "consensus/src/simplex/actors/voter/state.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(self.SOURCE)
        self.helper = self.root / "consensus/src/simplex/statelens.rs"
        self.helper.write_text(self.HELPER)
        second = AssertionScanner.PLAN.split("### ", 1)[1]
        second = second.replace("INV-0016", "INV-0017").replace("try_propose", "try_other")
        (self.root / "plan.md").write_text(AssertionScanner.PLAN + "\n### " + second)
        self.campaign = sl.Campaign.__new__(sl.Campaign)
        fields = dict(
            repo=self.root, dir=self.root, base=None, agent="fixture",
            profile_name="simplex", profile=sl.PROFILES["simplex"], targets=[],
            fuzz_toolchain="nightly",
            invariants=[("simplex", pathlib.Path("INV-0016.md")), ("simplex", pathlib.Path("INV-0017.md"))],
            config={"STATELENS_AUDIT": "1"}, statuses={"INV-0016": "bound", "INV-0017": "bound"},
            inactive=[], audited=None, coverage=None, plan_problems=None, sites=None,
            components=None, reason=None, panic=None, initialized=False,
        )
        for key, value in fields.items():
            setattr(self.campaign, key, value)
        self.campaign.invariant_prompts = lambda: []
        self.campaign.beacon_prompts = lambda: []
        self.campaign.audit_prompts = lambda: [
            ("audit-simplex-1", self.FIRST), ("audit-simplex-2", self.SECOND)
        ]
        self.campaign.check_scope = lambda: None
        self.campaign.record = lambda: None
        self.campaign.build_once = lambda _attempt: None
        saved = sl.say
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(setattr, sl, "say", saved)

    def handover(self, second_batch=None, lint_clean=True):
        def agent_step(name, _prompt):
            if name == "audit-simplex-2" and second_batch:
                second_batch()

        self.campaign.agent_step = agent_step
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.campaign.instrument()
            self.campaign.build()
            self.campaign.finish(0, "READY")
        if lint_clean:
            self.assertEqual(self.campaign.plan_problems, 0, "the lint cannot see these edits")
        return out.getvalue()

    def test_a_later_batch_that_edits_a_helper_leaves_earlier_bindings_unreviewed(self):
        out = self.handover(
            lambda: self.helper.write_text(self.HELPER.replace("    required\n", "    true\n"))
        )
        self.assertEqual(
            self.campaign.unreviewed,
            {
                "INV-0016": (
                    "audit-simplex-2",
                    ["consensus/src/simplex/statelens.rs (changed or removed lines)"],
                )
            },
        )
        self.assertIn(
            "coverage   UNVALIDATED: audit batch audit-simplex-2 edited "
            "consensus/src/simplex/statelens.rs (changed or removed lines) after the verdict "
            "on INV-0016, which were not reviewed against the edit",
            out,
        )
        self.assertIn("result     READY", out)

    def test_lines_added_inside_an_existing_body_are_an_edit(self):
        # The gap: a pure insertion was quiet wherever it landed, but a `let` that
        # shadows the argument changes what the earlier assertion evaluates.
        out = self.handover(
            lambda: self.helper.write_text(
                self.HELPER.replace("{\n", "{\n    let required = true;\n")
            )
        )
        self.assertIn("UNVALIDATED", out)
        self.assertEqual(
            self.campaign.unreviewed["INV-0016"][1],
            ["consensus/src/simplex/statelens.rs (added lines inside `evidence`)"],
        )

    def test_a_check_added_inside_a_body_is_quiet(self):
        def add_check():
            self.source.write_text(
                self.SOURCE.replace(
                    '        sl_assert!(None, "INV-0017", evidence(required), "b");\n',
                    '        sl_assert!(None, "INV-0017", evidence(required), "b");\n'
                    "        // [statelens] INV-0017\n"
                    "        crate::simplex::statelens::sl_implies!(\n"
                    "            None,\n"
                    '            "INV-0017",\n'
                    "            required,\n"
                    "            evidence(required),\n"
                    '            "b again: {}", required\n'
                    "        );\n",
                )
            )

        out = self.handover(add_check)
        self.assertEqual(self.campaign.unreviewed, {})
        self.assertNotIn("UNVALIDATED", out)

    def test_an_attribute_or_comment_opener_above_an_item_is_an_edit(self):
        for edit, expected in (
            (
                lambda: self.helper.write_text("#[cfg(any())]\n" + self.HELPER),
                "added an attribute or a comment opener above an item",
            ),
            (
                lambda: self.source.write_text(
                    self.SOURCE.replace(
                        '        sl_assert!(None, "INV-0016", evidence(required), "a");\n',
                        "        /*\n"
                        '        sl_assert!(None, "INV-0016", evidence(required), "a");\n'
                        "        */\n",
                    )
                ),
                "added lines inside `try_propose`",
            ),
        ):
            with self.subTest(expected=expected):
                self.setUp()
                # Commenting the check out is also a lint problem; the drift check
                # must name the edit regardless.
                out = self.handover(edit, lint_clean=False)
                self.assertIn("UNVALIDATED", out)
                self.assertIn(expected, self.campaign.unreviewed["INV-0016"][1][0])

    def test_an_appended_copy_of_an_earlier_block_is_an_addition(self):
        # A diff pairs the old block with its later copy and calls the lines between
        # removed; the subsequence walk sees every old line survive.
        twice = self.HELPER + "pub fn more() -> bool { true }\n" + self.HELPER.replace(
            "evidence", "evidence_again"
        )
        out = self.handover(lambda: self.helper.write_text(twice))
        self.assertEqual(self.campaign.unreviewed, {})
        self.assertNotIn("UNVALIDATED", out)

    def test_the_plan_summary_records_the_unreviewed_bindings(self):
        run = lambda *args: subprocess.run(  # noqa: E731
            ("git",) + args, cwd=self.root, capture_output=True, text=True, check=True
        )
        run("init", "-q", ".")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        run("config", "commit.gpgsign", "false")
        run("add", "-A")
        run("commit", "-qm", "base")
        del self.campaign.record
        self.campaign.unreviewed = {
            "INV-0016": ("audit-simplex-2", ["consensus/src/simplex/statelens.rs (changed or removed lines)"])
        }
        self.campaign.record()
        summary = (self.root / "plan.md").read_text().split("## Summary", 1)[1]
        self.assertIn(
            "- Audit: audit batch audit-simplex-2 edited consensus/src/simplex/statelens.rs "
            "(changed or removed lines) after the verdict on INV-0016",
            summary,
        )

    def test_a_later_batch_that_only_adds_lines_leaves_nothing_unreviewed(self):
        def add():
            self.helper.write_text(self.HELPER + "pub fn more() -> bool { true }\n")
            self.source.write_text(
                self.SOURCE.replace("    fn try_other", '    // [statelens] INV-0017\n    fn try_other')
            )

        out = self.handover(add)
        self.assertEqual(self.campaign.unreviewed, {})
        self.assertNotIn("UNVALIDATED", out)

    def test_a_removed_line_counts_as_an_edit(self):
        out = self.handover(lambda: self.helper.write_text(""))
        self.assertEqual(list(self.campaign.unreviewed), ["INV-0016"])
        self.assertIn("UNVALIDATED", out)

    def test_the_task_line_names_the_batch(self):
        prompt = (
            "# StateLens instrumenter\n\n## Task: audit the bindings of invariants INV-0001, "
            "INV-0002 of the simplex registry\n\nINV-0003 and INV-0004 cover the rest.\n"
        )
        self.assertEqual(sl.prompt_invariants(prompt), ["INV-0001", "INV-0002"])
        self.assertEqual(sl.prompt_invariants("INV-0016"), ["INV-0016"])
        self.assertFalse(sl.modified_lines("", "new file\n"))
        self.assertFalse(sl.modified_lines("a\nb\n", "a\nb\nc\n"))
        self.assertTrue(sl.modified_lines("a\nb\n", "a\nB\n"))
        self.assertTrue(sl.modified_lines("a\nb\n", "a\n"))


class PromptCopies(unittest.TestCase):
    """Section 13 of the specification claims to reproduce every prompt verbatim.
    Nothing enforced it, and two prompts had drifted from their copies, so the
    specification described rules the agents were never given."""

    SPEC = (
        "# Spec\n\n## 13. Prompts (verbatim)\n\n"
        "### 13.1 `prompts/one.md`\n\n~~~markdown\nfirst\n~~~\n\n"
        "### 13.2 `prompts/two.md`\n\n~~~markdown\nsecond\n~~~\n\n## 14. Next\n"
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        (self.sl_dir / "prompts").mkdir(parents=True)
        (self.sl_dir / "docs").mkdir(parents=True)
        self.spec = self.repo / sl.SPEC_DOC
        self.spec.write_text(self.SPEC)
        (self.sl_dir / "prompts/one.md").write_text("first\n")
        (self.sl_dir / "prompts/two.md").write_text("second\n")
        self.saved = sl.say
        sl.say = lambda *_args, **_kwargs: None
        self.addCleanup(lambda: setattr(sl, "say", self.saved))

    def test_matching_copies_are_clean(self):
        self.assertEqual(sl.lint_prompts(self.repo), [])

    def test_a_drifted_copy_is_reported(self):
        (self.sl_dir / "prompts/two.md").write_text("second, with a new rule\n")
        problems = sl.lint_prompts(self.repo)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("differs from its copy", problems[0][1])

    def test_write_refreshes_the_copy_and_leaves_the_rest_alone(self):
        (self.sl_dir / "prompts/one.md").write_text("first, with a new rule\n")
        sl.lint_prompts(self.repo, write=True)
        self.assertEqual(sl.lint_prompts(self.repo), [])
        text = self.spec.read_text()
        self.assertIn("first, with a new rule\n~~~", text)
        self.assertIn("### 13.2 `prompts/two.md`\n\n~~~markdown\nsecond\n~~~", text)
        self.assertTrue(text.endswith("## 14. Next\n"), "the rest of the document must survive")

    def test_write_refreshes_several_stale_copies_at_once(self):
        (self.sl_dir / "prompts/one.md").write_text("first, rewritten\n")
        (self.sl_dir / "prompts/two.md").write_text("second, rewritten\n")
        sl.lint_prompts(self.repo, write=True)
        self.assertEqual(sl.lint_prompts(self.repo), [])
        text = self.spec.read_text()
        self.assertIn("~~~markdown\nfirst, rewritten\n~~~", text)
        self.assertIn("~~~markdown\nsecond, rewritten\n~~~", text)

    def test_a_prompt_that_quotes_a_fence_round_trips(self):
        (self.sl_dir / "prompts/two.md").write_text("second\n\n~~~markdown\ninner\n~~~\n\ntail\n")
        sl.lint_prompts(self.repo, write=True)
        self.assertEqual(sl.lint_prompts(self.repo), [], "a quoted fence must not end the block")
        self.assertTrue(self.spec.read_text().endswith("## 14. Next\n"))

    def test_a_prompt_with_no_copy_is_reported(self):
        (self.sl_dir / "prompts/three.md").write_text("third\n")
        problems = sl.lint_prompts(self.repo)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("has no `### 13.N", problems[0][1])

    def test_a_copy_with_no_prompt_is_reported(self):
        (self.sl_dir / "prompts/two.md").unlink()
        problems = sl.lint_prompts(self.repo)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("which does not exist", problems[0][1])



class PlanProfile(unittest.TestCase):
    """The audit prompt runs `lint-plan` with no profile, so in a qmdb campaign the
    bare command must check the qmdb registry, not the simplex default."""

    PLAN = (
        "# StateLens instrumentation plan\n\n## Invariants\n\n"
        "### INV-0034: Example\n- Status: unbound\n- Notes: fixture.\n"
    )

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        for registry, identifier in (("simplex", "INV-0001"), ("qmdb", "INV-0034")):
            directory = self.sl_dir / "invariants" / registry
            directory.mkdir(parents=True)
            (directory / f"{identifier}.md").write_text("unused by the plan lint\n")
        (self.sl_dir / "campaign").mkdir()
        (self.repo / sl.PLAN).write_text(self.PLAN)
        saved = {name: getattr(sl, name) for name in ("repo_root", "say")}
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_args, **_kw: None
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])

    def lint(self, *flags, profile="qmdb"):
        if profile:
            meta = self.sl_dir / "campaign" / "meta.json"
            meta.write_text(json.dumps({"profile": profile}))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sl.main(["lint-plan", *flags])
        return code, out.getvalue()

    def test_the_bare_command_checks_the_campaign_profile(self):
        code, output = self.lint()
        self.assertEqual(code, 0, output)

    def test_an_explicit_profile_wins(self):
        code, output = self.lint("--profile", "simplex")
        self.assertEqual(code, 3, output)
        self.assertIn("INV-0001: has no section", output)

    def test_without_a_campaign_the_default_is_simplex(self):
        code, output = self.lint(profile=None)
        self.assertEqual(code, 3, output)
        self.assertIn("INV-0001: has no section", output)

    def test_an_unknown_campaign_profile_is_refused(self):
        code, _output = self.lint(profile="nonsense")
        self.assertEqual(code, 1)

class QmdbProfile(unittest.TestCase):
    """The qmdb profile instruments storage, not consensus: its own crate, runtime
    path, anchors, fuzz package and tests, with every target derived the same way."""

    REPO = HERE.parents[1]

    def test_the_sources_are_the_qmdb_targets_of_the_storage_package(self):
        directory = self.REPO / "storage/fuzz/fuzz_targets"
        expected = sorted(
            path.stem for path in directory.glob("qmdb_*.rs")
            if not path.stem.endswith("_statelens")
        )
        self.assertTrue(expected)
        self.assertEqual(sl.profile_sources(self.REPO, "qmdb"), expected)

    def test_materialize_edits_storage_and_no_consensus_file(self):
        edits = sl.materialize_edits(self.REPO, self.REPO / sl.SL, "qmdb")
        self.assertEqual(
            sorted(edits.modify),
            [
                "runtime/src/deterministic.rs",
                "storage/Cargo.toml",
                "storage/fuzz/Cargo.toml",
                "storage/src/qmdb/mod.rs",
            ],
        )
        self.assertIn("pub mod statelens;", edits.modify["storage/src/qmdb/mod.rs"])
        self.assertIn("sancov.workspace = true", edits.modify["storage/Cargo.toml"])
        runtime = edits.create[sl.QMDB_RS]
        self.assertIn("crate::qmdb::statelens::sl_probe!", runtime)
        self.assertNotIn("simplex::", runtime, "the module path must be renamed")
        self.assertNotIn(sl.RUNTIME_CONSENSUS_ONLY, runtime, "consensus tests must be left out")
        self.assertTrue(runtime.endswith("}\n"))
        self.assertEqual(len(edits.create), 1 + len(edits.targets))
        manifest = edits.modify["storage/fuzz/Cargo.toml"]
        for target in edits.targets:
            text = edits.create[f"storage/fuzz/fuzz_targets/{target}.rs"]
            self.assertEqual(text.count("commonware_storage::qmdb::statelens::reset();"), 1)
            self.assertEqual(
                text.count("commonware_storage::qmdb::statelens::clear_compromised();"), 1
            )
            self.assertIn(f'name = "{target}"', manifest)

    def test_the_consensus_profiles_copy_the_template_unchanged(self):
        template = (self.REPO / sl.SL / "runtime/statelens.rs").read_text()
        self.assertEqual(template.count(sl.RUNTIME_CONSENSUS_ONLY), 1)
        for profile in ("simplex", "marshal"):
            self.assertEqual(sl.runtime_text(self.REPO, profile), template)

    def test_the_gate_runs_the_qmdb_tests_of_storage(self):
        command = sl.gate_test_command("stable", "qmdb")
        self.assertEqual(command[command.index("-p") + 1], "commonware-storage")
        self.assertEqual(command[-1], "test(/^qmdb::/)")
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.profile, campaign.test_toolchain = sl.PROFILES["qmdb"], "stable"
        self.assertEqual(
            campaign.check_command(),
            ["cargo", "+stable", "check", "-p", "commonware-storage", "--lib", "--tests"],
        )

    def test_the_handover_runs_through_this_subproject(self):
        campaign = sl.Campaign.__new__(sl.Campaign)
        campaign.repo = pathlib.Path("/repo")
        campaign.profile = sl.PROFILES["qmdb"]
        campaign.fuzz_toolchain = "nightly-x"
        campaign.targets = ["qmdb_verify_proof_statelens"]
        rows = dict(campaign.handover())
        self.assertEqual(
            rows["run"],
            "cd /repo/statelens && NIGHTLY_VERSION=nightly-x just run "
            "qmdb_verify_proof_statelens -- -rss_limit_mb=4000 -print_final_stats=1",
        )
        self.assertEqual(
            rows["replay"],
            "cd /repo/statelens && NIGHTLY_VERSION=nightly-x just run "
            "qmdb_verify_proof_statelens "
            "/repo/storage/fuzz/artifacts/qmdb_verify_proof_statelens/<crash file>",
        )

    def test_each_profile_renders_its_own_runtime_into_the_prompts(self):
        sl_dir = self.REPO / sl.SL
        for profile, runtime, module, package in (
            ("simplex", sl.STATELENS_RS, "crate::simplex::statelens", "consensus/fuzz/simplex"),
            ("qmdb", sl.QMDB_RS, "crate::qmdb::statelens", "storage/fuzz"),
        ):
            campaign = sl.Campaign.__new__(sl.Campaign)
            campaign.base, campaign.test_toolchain = "0" * 40, "stable"
            campaign.profile = sl.PROFILES[profile]
            registry = sl.PROFILES[profile]["registries"][-1]
            values = dict(
                campaign.common_values(),
                INVARIANT_IDS="INV-0001",
                INVARIANTS="(none)",
                REGISTRY=registry,
                SUBSYSTEM_RULES=sl.subsystem_prompt(sl_dir, registry, "instrument"),
            )
            for task in ("instrument-invariants.md", "instrument-audit.md"):
                text = sl.compose(sl_dir, "instrument.md", task, values)
                self.assertIn(f"Read `{runtime}` first", text)
                self.assertIn(f"## Runtime API (`{module}`)", text)
                self.assertIn(f"`{package}`", text)
                self.assertNotIn("{{", text)
            if profile == "qmdb":
                self.assertNotIn("simplex::statelens", text)

    def test_extract_reads_the_qmdb_context(self):
        values = sl.extract_values(
            self.REPO, self.REPO / sl.SL, "comment", "qmdb", ["storage/src/qmdb/mod.rs"]
        )
        self.assertEqual(values["SOURCE_ROOT"], "storage/src/qmdb")
        self.assertIn("System: `database`", values["CONTEXT"])
        prompt = sl.compose(self.REPO / sl.SL, "analyst.md", "analyst-comment.md", values)
        self.assertNotIn("{{", prompt)
        self.assertIn("`storage/src/qmdb`", prompt)


class VariantDerivation(unittest.TestCase):
    """Every profile derives a variant by putting a reset and a clear around the body of
    `fuzz_target!`, whatever the indent, the parameter or the form of the target."""

    RUNTIME = "commonware_x::m::statelens"

    def derive(self, text):
        lines, _anchors = sl.variant_text("t.rs", text.split("\n"), self.RUNTIME)
        return "\n".join(lines)

    def test_an_indented_block_keeps_its_indent(self):
        self.assertEqual(
            self.derive("mod m {\n    fuzz_target!(|input: In| {\n        go(input);\n    });\n}\n"),
            "mod m {\n    fuzz_target!(|input: In| {\n"
            "        commonware_x::m::statelens::reset();\n"
            "        go(input);\n"
            "        commonware_x::m::statelens::clear_compromised();\n"
            "    });\n}\n",
        )

    def test_a_top_level_block_over_bytes(self):
        self.assertEqual(
            self.derive("fuzz_target!(|data: &[u8]| {\n    go(data);\n});\n"),
            "fuzz_target!(|data: &[u8]| {\n"
            "    commonware_x::m::statelens::reset();\n"
            "    go(data);\n"
            "    commonware_x::m::statelens::clear_compromised();\n"
            "});\n",
        )

    def test_the_body_ends_at_the_closing_line_of_its_own_indent(self):
        derived = self.derive(
            "fuzz_target!(|input: In| {\n    run(|c| {\n        go(c);\n    });\n});\n"
        )
        self.assertTrue(
            derived.endswith(
                "    });\n    commonware_x::m::statelens::clear_compromised();\n});\n"
            ),
            derived,
        )

    def test_a_one_line_target_becomes_a_block(self):
        self.assertEqual(
            self.derive("use x;\nfuzz_target!(|input: In| fuzz(input));\n"),
            "use x;\nfuzz_target!(|input: In| {\n"
            "    commonware_x::m::statelens::reset();\n"
            "    fuzz(input);\n"
            "    commonware_x::m::statelens::clear_compromised();\n"
            "});\n",
        )

    def test_a_file_without_exactly_one_target_is_refused(self):
        for text in (
            "fn main() {}\n",
            "fuzz_target!(|a: A| {\n});\nfuzz_target!(|b: B| {\n});\n",
            "fuzz_target!(|input: In| {\n    go(input);\n",
        ):
            with self.assertRaises(sl.Abort):
                self.derive(text)


class IndexCrate(unittest.TestCase):
    """SCIP paths are relative to the indexed crate, which a qmdb campaign makes storage,
    so the loader must take the crate from the index rather than assume consensus."""

    def load(self, raw):
        directory = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        path = directory / "i.scip"
        path.write_bytes(raw)
        _occurrences, definitions, _names = sl.index_load(path)
        return definitions["sym"][0]

    def test_the_crate_comes_from_the_project_root(self):
        metadata = length_delimited(1, length_delimited(3, b"file:///work/repo/storage"))
        index = scip_index("src/qmdb/mod.rs", "sym", [0, 3, 4], [0, 0, 0, 9])
        self.assertEqual(self.load(metadata + index), "storage/src/qmdb/mod.rs")

    def test_an_index_without_metadata_is_of_consensus(self):
        index = scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9])
        self.assertEqual(self.load(index), "consensus/src/x.rs")

    def test_each_profile_indexes_its_own_crate(self):
        self.assertEqual(
            {name: settings["crate"] for name, settings in sl.PROFILES.items()},
            {"simplex": "consensus", "marshal": "consensus", "qmdb": "storage"},
        )



class IndexRebuildProfile(unittest.TestCase):
    """A query that finds edited sources says to run `just code-index`, which builds
    with no subsystem, so an omitted one must keep the crate in use rather than switch a
    qmdb checkout's index back to consensus."""

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.sl_dir = self.repo / sl.SL
        (self.sl_dir / "extract").mkdir(parents=True)
        (self.sl_dir / "campaign").mkdir()
        saved = {name: getattr(sl, name) for name in ("repo_root", "say", "index_build")}
        sl.repo_root = lambda: self.repo
        sl.say = lambda *_args, **_kw: None
        self.built = []
        sl.index_build = lambda _repo, _sl_dir, subsystem: self.built.append(subsystem) or True
        self.addCleanup(lambda: [setattr(sl, k, v) for k, v in saved.items()])

    def index(self, crate):
        root = length_delimited(3, f"file:///work/repo/{crate}".encode())
        sl.index_path(self.sl_dir).write_bytes(
            length_delimited(1, root) + scip_index("src/f.rs", "sym", [0, 3, 4], [0, 0, 0, 9])
        )

    def build(self, *flags, campaign=None):
        if campaign:
            (self.sl_dir / "campaign" / "meta.json").write_text(json.dumps({"profile": campaign}))
        self.assertEqual(sl.main(["code", "build", *flags]), 0)
        return self.built[-1]

    def test_the_advice_after_an_edit_keeps_a_qmdb_campaign_on_storage(self):
        source = self.repo / "storage/src/f.rs"
        source.parent.mkdir(parents=True)
        source.write_text("fn f() {}\n")
        self.index("storage")
        sl.snapshot_write(self.repo, self.sl_dir, ["storage/src/f.rs"])
        source.write_text("fn f() { let _edited = 1; }\n")
        self.assertIn("Rebuild with `just code-index`", sl.Rebaser(self.repo, self.sl_dir).report())
        self.assertEqual(self.build(campaign="qmdb"), "qmdb")

    def test_without_a_campaign_the_index_keeps_its_crate(self):
        self.index("storage")
        self.assertEqual(self.build(), "qmdb")
        self.index("consensus")
        self.assertEqual(self.build(), "simplex")

    def test_without_a_campaign_or_an_index_the_default_is_simplex(self):
        self.assertEqual(self.build(), "simplex")

    def test_an_explicit_subsystem_wins(self):
        self.index("storage")
        self.assertEqual(self.build("--subsystem", "marshal", campaign="qmdb"), "marshal")

class JustfileProfiles(unittest.TestCase):
    """`just fuzz` and `just run` decide by name which profile and which package a
    target belongs to, so each profile must be known to both recipes."""

    TEXT = (HERE.parent / "justfile").read_text()

    def recipe(self, name):
        return self.TEXT.split(f"\n{name} ", 1)[1].split("\n# ", 1)[0]

    def test_fuzz_accepts_every_profile_and_its_targets(self):
        fuzz = self.recipe("fuzz")
        self.assertIn("|".join(sl.PROFILES) + ")", fuzz)
        for profile in sl.PROFILES:
            self.assertRegex(fuzz, rf"\n\s+{profile}_\*\)\s+profile={profile};")

    def test_run_reaches_every_package(self):
        run = self.recipe("run")
        for profile, settings in sl.PROFILES.items():
            package = settings["package"]
            if package.startswith("consensus/fuzz/"):
                # consensus/fuzz's own `run` finds the package that defines a target.
                self.assertIn("cd ../consensus/fuzz && just run", run)
                continue
            self.assertIn(f"{profile}_*)", run)
            self.assertIn(f"--fuzz-dir {package}", run)


class QmdbRegistry(unittest.TestCase):
    """The qmdb registry takes its own scope values and no other registry's."""

    def lint(self, scope):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        path = root / "invariants" / "qmdb" / "INV-0001.md"
        path.parent.mkdir(parents=True)
        path.write_text(
            "---\nid: INV-0001\ntitle: A title\nsource_kind: human\n"
            f"source_ref: storage/src/qmdb/mod.rs\nscope: [{scope}]\n---\n\n"
            "## Statement\nThe database shall keep its root.\n\n## Rationale\nIt must.\n\n"
            "## Evidence\nHuman-authored.\n"
        )
        return sl.lint_file(path)

    def test_qmdb_scopes_are_accepted(self):
        self.assertEqual(self.lint("database, current"), [])

    def test_another_registry_scope_is_refused(self):
        self.assertEqual(
            self.lint("voter"),
            [
                "scope must be a list of the qmdb registry's values: "
                + ", ".join(sl.SCOPES["qmdb"])
            ],
        )

    def test_every_registry_has_a_false_invariant(self):
        root = HERE.parent / "false-invariants"
        for registry in sl.SUBSYSTEMS:
            self.assertTrue(list((root / registry).glob("FALSE-*.md")), registry)


if __name__ == "__main__":
    unittest.main(verbosity=2)
