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
        self.sl_dir = self.repo / "consensus/fuzz/statelens"
        (self.sl_dir / "extract").mkdir(parents=True)
        self.index = sl.index_path(self.sl_dir)
        self._which, self._run, self._say = sl.shutil.which, sl.run_logged, sl.say
        sl.shutil.which = lambda _name: "/usr/bin/rust-analyzer"
        sl.say = lambda *_args, **_kw: None

    def tearDown(self):
        sl.shutil.which, sl.run_logged, sl.say = self._which, self._run, self._say

    def stub(self, _command, _log, cwd=None, stdin_text=None):
        """A successful run that leaves a real index behind, so the snapshot
        step runs exactly as it does in a campaign."""
        # SCIP paths are relative to the indexed crate, and index_load
        # prefixes them, so the file has to live under consensus/.
        (self.repo / "consensus/src").mkdir(parents=True, exist_ok=True)
        (self.repo / "consensus/src/x.rs").write_text("fn f() {}\n")
        self.index.write_bytes(scip_index("src/x.rs", "sym", [0, 3, 4], [0, 0, 0, 9]))
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
        # The index is queryable even when the snapshot cannot be taken.
        def stub(_command, _log, cwd=None, stdin_text=None):
            self.index.write_bytes(b"\x1f\x8bnot protobuf")
            return 0, []

        sl.run_logged = stub
        self.assertEqual(sl.index_build(self.repo, self.sl_dir, "simplex"), self.index)
        self.assertFalse(sl.snapshot_path(self.sl_dir).exists())

    def test_nonzero_exit_returns_none(self):
        sl.run_logged = lambda *_a, **_kw: (1, ["error"])
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))

    def test_zero_exit_but_no_file_returns_none(self):
        sl.run_logged = lambda *_a, **_kw: (0, [])
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))

    def test_missing_rust_analyzer_returns_none(self):
        sl.shutil.which = lambda _name: None
        self.assertIsNone(sl.index_build(self.repo, self.sl_dir, "simplex"))


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
            "struct S { armed: bool }\n"
            "impl S {\n"
            "    fn new() -> S { S { armed: false } }\n"
            "    fn arm(&mut self) { self.armed = true; }\n"
            "    fn ready(&self) -> bool { self.armed }\n"
            "    fn armed(&self) -> bool { self.armed }\n"
            "}\n"
        )

    def test_classifies_write_init_and_read(self):
        writes, reads, inits, opaque = sl.ast_field_ops(self.path, "armed")
        self.assertEqual(opaque, [], "no macro bodies in this fixture")
        # `self.armed = true` is a write, not a read of the `self` path.
        self.assertEqual(writes, [4])
        # a struct literal field is an initial value, not a write
        self.assertEqual(inits, [3])
        # the two bodies that read it; the method declaration on line 6 is a
        # different entity of the same spelling and is not counted
        self.assertEqual(reads, [5, 6])


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
        self.sl_dir = self.repo / "consensus/fuzz/statelens"
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
        writes, reads, inits, opaque = sl.ast_field_ops(self.path, "armed")
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
        self.sl_dir = self.repo / "consensus/fuzz/statelens"
        (self.sl_dir / "invariants/simplex").mkdir(parents=True)
        (self.repo / "README.md").write_text("original\n")
        self.run_git("init", "-q", ".")
        self.run_git("config", "user.email", "t@example.invalid")
        self.run_git("config", "user.name", "t")
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
                                   sources=["x"])
            )
        return code, out.getvalue()

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
        self.repo = HERE.parents[3]
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


def scip_document(relative, occurrences):
    """A SCIP index of one document holding several occurrences.

    Each occurrence is (symbol, span, enclosing or None, roles).
    """
    body = length_delimited(1, relative.encode())
    for symbol, span, enclosing, roles in occurrences:
        one = length_delimited(1, packed(*span)) + length_delimited(2, symbol.encode())
        one += tag(3, 0) + packed(roles)
        if enclosing:
            one += length_delimited(7, packed(*enclosing))
        body += length_delimited(2, one)
    return length_delimited(2, body)


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
        self.sl_dir = self.repo / "consensus/fuzz/statelens"
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
        _writes, reads, _inits, opaque = sl.ast_field_ops(path, "armed")
        self.assertEqual(len(opaque), 1, "the write far into the body must be seen")
        self.assertNotIn(opaque[0], reads)


class PromptPaths(unittest.TestCase):
    """Phase 2 runs the agent from the repository root, so prompt paths are
    relative to it, not to this subproject. The script lives four levels down,
    and a prompt that says `scripts/statelens.py` fails there."""

    REPO = HERE.parents[3]
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
                    "consensus/fuzz/statelens/scripts/statelens.py",
                    line,
                    f"{path.name}:{line_number} names the script relative to this "
                    f"subproject, but the agent runs from the repository root",
                )

    def test_referenced_subproject_files_exist(self):
        reference = __import__("re").compile(
            r"consensus/fuzz/statelens/[A-Za-z0-9_./-]+[A-Za-z0-9_/]"
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


class CoverageSelection(unittest.TestCase):
    """`just coverage` takes the names `just fuzz` takes, so a marshal target must
    not be covered against the simplex profile's package, and a typo must name the
    targets that exist rather than silently covering all of them."""

    def select(self, *names, profile=None):
        return sl.coverage_selection(
            HERE.parents[3], argparse.Namespace(profile=profile, targets=list(names))
        )

    def test_no_name_covers_every_target_of_the_default_profile(self):
        profile, targets = self.select()
        self.assertEqual(profile, "simplex")
        self.assertEqual(targets, sl.profile_targets(HERE.parents[3], "simplex"))

    def test_a_profile_name_covers_that_profile(self):
        profile, targets = self.select("marshal")
        self.assertEqual(profile, "marshal")
        self.assertEqual(targets, sl.profile_targets(HERE.parents[3], "marshal"))

    def test_a_target_name_implies_its_profile(self):
        profile, targets = self.select("marshal_scenario_standard_inline_cert_mock_statelens")
        self.assertEqual(profile, "marshal")
        self.assertEqual(targets, ["marshal_scenario_standard_inline_cert_mock_statelens"])

    def test_a_name_of_neither_profile_is_refused(self):
        with self.assertRaises(sl.Abort) as caught:
            self.select("nonsense")
        self.assertIn("not a profile", str(caught.exception))

    def test_a_target_the_profile_does_not_build_is_refused(self):
        with self.assertRaises(sl.Abort) as caught:
            self.select("simplex_does_not_exist")
        self.assertIn("builds no target", str(caught.exception))

    def test_the_report_is_scoped_to_what_the_profile_instruments(self):
        repo = HERE.parents[3]
        for profile in ("simplex", "marshal"):
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
            ("INV-0016", "try_propose"),
            ("INV-0016", "construct_notarize"),
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
