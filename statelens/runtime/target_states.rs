//! Target-State Synthesis helper for the scaffolds of one fuzz package.
//!
//! This file is a template kept in `statelens/runtime/`. A synthesis copies it to
//! `<package>/src/target_states/mod.rs`, followed by one `pub mod tsNNNN_<base>;` line per
//! scaffold module, in a checkout a campaign instrumented. It is never compiled on a
//! committed branch.
//!
//! A scaffold splits and picks its knobs ([Knobs]), opens its stages
//! ([Stages::new]) and checks its budget ([Stages::budget]) before any engine
//! starts. It records each stage `E1` to `E(n-1)` through a [Witness]
//! ([Stages::held]) or another outcome, and the last one, `En`, through
//! [Stages::handoff], which decides the handoff. The helper takes every position
//! of the event sequence itself: a witness read, an entry a recording wrapper
//! stamps ([stamp]), an action ([Witness::act]), a restart boundary ([restart]),
//! and the start and the mark of the handoff. It prints the lines the reach check
//! parses, adds the feature of every held stage, and raises the only errors
//! attributed to a scaffold, all before any engine starts.
//!
//! Once the trace drops an observation at its cap, what it holds from that position
//! on is incomplete, so the helper prints a `truncated` line with the position, at
//! its first event after the cut, and neither a stage read at or after the cut nor
//! a handoff whose mark follows it holds.
//!
//! Environment switches, each read once per process:
//! - `STATELENS_REACH=1` prints the `[statelens-reach]` lines on stderr.
//! - `STATELENS_REACH_CONTROL=1` makes [control] true: the control run.

// A scaffold module is a child of this one, and a child module can use every
// private item of its parent. The helper's code is therefore in a private module of
// its own, `imp`, whose private items no scaffold can reach, and this one
// re-exports its API.
pub use imp::{Knobs, Stages, Stamp, Witness, control, restart, stamp};

mod imp {
    use commonware_consensus::simplex::statelens::{self, Seen};
    use std::{cell::RefCell, fmt, future::Future, io::Write as _, sync::OnceLock, time::Duration};

    /// Most knobs a scaffold splits.
    const MAX_KNOBS: usize = 16;

    /// Most `trace` lines a miss prints.
    const TRACE_LINES: usize = 64;

    /// The reason of a stage read after the trace dropped an observation.
    const TRUNCATED: &str = "(trace truncated)";

    thread_local! {
        static STATE: RefCell<State> = const { RefCell::new(State::new()) };
    }

    /// Whether `STATELENS_REACH=1`: the lines print only then.
    fn reach() -> bool {
        static REACH: OnceLock<bool> = OnceLock::new();
        *REACH.get_or_init(|| std::env::var("STATELENS_REACH").is_ok_and(|value| value == "1"))
    }

    /// Whether `STATELENS_REACH_CONTROL=1`, read once: the control run, in which the
    /// scaffold withholds the event its header names and a miss does not close the
    /// prefix.
    pub fn control() -> bool {
        static CONTROL: OnceLock<bool> = OnceLock::new();
        *CONTROL.get_or_init(|| {
            std::env::var("STATELENS_REACH_CONTROL").is_ok_and(|value| value == "1")
        })
    }

    /// Prints one line of card `card`, under `STATELENS_REACH=1`.
    fn emit(card: &str, line: &str) {
        if card.is_empty() {
            return;
        }
        #[cfg(test)]
        tests::LINES.with(|lines| lines.borrow_mut().push(line.to_string()));
        if reach() {
            let text = format!("[statelens-reach] {card} {line}\n");
            let _ = std::io::stderr().write_all(text.as_bytes());
        }
    }

    /// Adds the feature of stage `k` of card `card`, which held.
    fn feature(card: &str, k: u32) {
        #[cfg(test)]
        tests::FEATURES.with(|features| features.borrow_mut().push(k));
        statelens::record(statelens::site_hash(card), k, 0);
    }

    /// Takes a position of the event sequence for a helper event, and notices a cut.
    fn position() -> u64 {
        let seq = statelens::tick();
        truncation();
        seq
    }

    /// The position of the first observation the trace dropped at its cap, or `None`.
    /// The first time it finds one while stages are open on this thread, it prints
    /// the `truncated` line.
    fn truncation() -> Option<u64> {
        let seq = statelens::truncated()?;
        let card = STATE.with(|state| {
            let mut state = state.borrow_mut();
            let first = !std::mem::replace(&mut state.noticed, true);
            first.then_some(state.card)
        });
        if let Some(card) = card {
            emit(card, &format!("truncated seq={seq}"));
        }
        Some(seq)
    }

    /// Raises a scaffold error. Only the checks that run before any engine starts
    /// call it, so the error depends on the scaffold's own code and knob bytes.
    #[cold]
    fn scaffold_error(card: &str, reason: fmt::Arguments<'_>) -> ! {
        panic!("[statelens-scaffold] {card} {reason}");
    }

    /// `text` with every character `bad` accepts, and whitespace, replaced by `_`,
    /// or `-` when it is empty, so a line keeps its fields apart.
    fn token(text: &str, bad: &[char]) -> String {
        if text.is_empty() {
            return "-".to_string();
        }
        text.chars()
            .map(|c| {
                if c.is_whitespace() || bad.contains(&c) {
                    '_'
                } else {
                    c
                }
            })
            .collect()
    }

    /// `text` without the whitespace at its ends and next to each of `separators`,
    /// so `R=2@E1, v=5@E1` keeps its entities apart.
    fn tidy(text: &str, separators: &[char]) -> String {
        let separator = |c: char| separators.contains(&c);
        let mut out = String::with_capacity(text.len());
        for piece in text.split_inclusive(separator) {
            let part = piece.strip_suffix(separator).unwrap_or(piece);
            out.push_str(part.trim());
            out.push_str(&piece[part.len()..]);
        }
        out
    }

    /// An observable or a verb.
    fn field_name(text: &str) -> String {
        token(text, &['[', ']', ',', '@', '='])
    }

    /// A key, `name=value,...`, which may be empty.
    fn field_key(text: &str) -> String {
        let text = tidy(text, &[',', '=']);
        if text.is_empty() {
            return text;
        }
        token(&text, &['[', ']', '@'])
    }

    /// A value read or bound.
    fn field_value(text: &str) -> String {
        token(text, &['[', ']', ',', '@'])
    }

    /// A detail or reason: the rest of its line.
    fn field_detail(text: &str) -> String {
        text.replace(['\n', '\r'], " ")
    }

    /// An action, `verb[name=value,...]`; a bare verb fixes no entity.
    fn field_action(text: &str) -> String {
        let (verb, entities) = match text.split_once('[') {
            Some((verb, rest)) => (verb, rest.strip_suffix(']').unwrap_or(rest)),
            None => (text, ""),
        };
        format!("{}[{}]", field_name(verb.trim()), field_key(entities))
    }

    /// `bind`, `name=value@Ek,...`, as one field of its line.
    fn field_bind(bind: &str) -> String {
        token(&tidy(bind, &[',', '=', '@']), &[])
    }

    /// The knobs of a scaffold: the first bytes of its base input's `raw_bytes`.
    #[derive(Debug)]
    pub struct Knobs {
        card: &'static str,
        bytes: Vec<u8>,
        next: usize,
    }

    impl Knobs {
        /// Forgets the stages of an earlier input on this thread, so a scaffold
        /// error before [Stages::new] prints none of them. Then takes the first `k`
        /// bytes of `raw`, zero-padded, for card `card`, and leaves the rest; a tail
        /// left empty from a non-empty `raw` becomes `[0]`. More than 16 knobs is a
        /// scaffold error.
        pub fn split(card: &'static str, raw: &mut Vec<u8>, k: usize) -> Self {
            STATE.with(|state| *state.borrow_mut() = State::new());
            if k > MAX_KNOBS {
                scaffold_error(card, format_args!("more than {MAX_KNOBS} knobs: {k}"));
            }
            let had_bytes = !raw.is_empty();
            let mut bytes: Vec<u8> = raw.drain(..k.min(raw.len())).collect();
            bytes.resize(k, 0);
            if had_bytes && raw.is_empty() {
                raw.push(0);
            }
            Self {
                card,
                bytes,
                next: 0,
            }
        }

        /// The next knob: `domain[byte % domain.len()]`, so byte 0 picks
        /// `domain[0]`, the source value. A domain with fewer than two values, or
        /// more knobs picked than split, is a scaffold error.
        pub fn pick<T: Copy>(&mut self, domain: &[T]) -> T {
            if domain.len() < 2 {
                scaffold_error(
                    self.card,
                    format_args!(
                        "knob {} has a domain of {} value(s); it needs two or more",
                        self.next,
                        domain.len()
                    ),
                );
            }
            let Some(&byte) = self.bytes.get(self.next) else {
                scaffold_error(
                    self.card,
                    format_args!("more knobs picked than split ({})", self.bytes.len()),
                );
            };
            self.next += 1;
            domain[usize::from(byte) % domain.len()]
        }
    }

    /// The position an entry took when a recording wrapper stamped it. Only [stamp]
    /// makes one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Stamp {
        seq: u64,
        run: u32,
    }

    impl Stamp {
        /// The entry's position; 0 when nothing watched.
        pub const fn seq(self) -> u64 {
            self.seq
        }
    }

    /// Stamps an entry a recording wrapper records, as it records it: takes a
    /// position, prints the `entry` line with it and returns it. Returns a stamp of
    /// position 0 and prints nothing while not watching.
    ///
    /// `observable` names what the wrapper records, `key` the entities the entry is
    /// keyed by, `name=value,...`, and `value` the value it records.
    pub fn stamp(observable: &str, key: &str, value: &str) -> Stamp {
        let seq = position();
        let run = statelens::current_run();
        if seq != 0 {
            emit(
                &card(),
                &format!(
                    "entry {}[{}]={} seq={seq}",
                    field_name(observable),
                    field_key(key),
                    field_value(value)
                ),
            );
        }
        Stamp { seq, run }
    }

    /// Marks an incarnation boundary of `replicas`, a restart the scaffold drives or
    /// a base's restart code runs: takes a position `s`, prints the `restart` line
    /// and returns `s`, which names the incarnation the restart began, `inc<s>`.
    /// Returns 0 and prints nothing while not watching.
    pub fn restart(replicas: &[u32]) -> u64 {
        let seq = position();
        if seq != 0 {
            let list: Vec<String> = replicas.iter().map(u32::to_string).collect();
            let list = if list.is_empty() {
                "-".to_string()
            } else {
                list.join(",")
            };
            emit(
                &card(),
                &format!("restart {list} seq={seq} run={}", statelens::current_run()),
            );
        }
        seq
    }

    /// The card of the stages open on this thread, or an empty string.
    fn card() -> String {
        STATE.with(|state| state.borrow().card.to_string())
    }

    /// What establishes a held stage, with the entities it binds.
    #[derive(Clone, Debug)]
    pub struct Witness {
        kind: &'static str,
        bind: String,
        evidence: String,
        /// The position the witness took when it was built.
        read: u64,
        /// The largest position its evidence carries, with its run; none for an
        /// `exact` witness with an item that has no stamp.
        position: Option<(u64, u32)>,
    }

    impl Witness {
        /// An `exact` witness: harness observables, one per part of the line, each
        /// read as `(observable, key, value, stamp)`, with the entry's stamp when the
        /// observable has one. `bind` is `name=value@Ek,...`, and each `key` names
        /// the entities it is keyed by, `name=value,...`. Its position is its latest
        /// stamp's, and it has none when an item has no stamp. Takes a position, its
        /// `read=`.
        pub fn exact(bind: &str, reads: &[(&str, &str, &str, Option<Stamp>)]) -> Self {
            let read = position();
            let evidence: Vec<String> = reads
                .iter()
                .map(|(observable, key, value, stamp)| {
                    let seq = stamp
                        .filter(|stamp| stamp.seq != 0)
                        .map_or_else(|| "-".to_string(), |stamp| stamp.seq.to_string());
                    format!(
                        "exact={}[{}]={} seq={seq}",
                        field_name(observable),
                        field_key(key),
                        field_value(value)
                    )
                })
                .collect();
            let stamps: Option<Vec<Stamp>> = reads
                .iter()
                .map(|read| read.3.filter(|stamp| stamp.seq != 0))
                .collect();
            let position = stamps
                .and_then(|stamps| stamps.into_iter().max_by_key(|stamp| stamp.seq))
                .map(|stamp| (stamp.seq, stamp.run));
            Self {
                kind: "exact",
                bind: field_bind(bind),
                evidence: evidence.join(" "),
                read,
                position,
            }
        }

        /// An `intrinsic` witness: one probe observation whose values come from one
        /// receiver. It identifies only the replica `me`, so `bind` gives every other
        /// entity `?`. Takes a position, its `read=`.
        pub fn intrinsic(bind: &str, seen: Seen) -> Self {
            let read = position();
            Self {
                kind: "intrinsic",
                bind: field_bind(bind),
                evidence: format!("obs={}", observation(seen)),
                read,
                position: Some((seen.seq(), seen.run())),
            }
        }

        /// A `construction` witness: takes a position right before it calls
        /// `perform`, which performs the harness action, and returns `perform`'s
        /// result with the witness. `action` is `verb[name=value,...]`. Before
        /// [Stages::new] nothing watches, so the position is 0 and the witness has
        /// none.
        pub fn act<T>(bind: &str, action: &str, perform: impl FnOnce() -> T) -> (T, Self) {
            let seq = position();
            let run = statelens::current_run();
            let result = perform();
            (
                result,
                Self::construction(field_bind(bind), field_action(action), seq, run),
            )
        }

        /// [Witness::act] for an action that is awaited: the returned future, when
        /// first polled, takes the position and only then calls `perform` and awaits
        /// the future it returns, so an action that takes effect when it is called
        /// still comes after its position.
        pub fn act_async<T, F, P>(
            bind: &str,
            action: &str,
            perform: P,
        ) -> impl Future<Output = (T, Self)> + use<T, F, P>
        where
            F: Future<Output = T>,
            P: FnOnce() -> F,
        {
            let bind = field_bind(bind);
            let action = field_action(action);
            async move {
                let seq = position();
                let run = statelens::current_run();
                let result = perform().await;
                (result, Self::construction(bind, action, seq, run))
            }
        }

        fn construction(bind: String, action: String, seq: u64, run: u32) -> Self {
            Self {
                kind: "construction",
                bind,
                evidence: format!("action={action} seq={seq}"),
                read: seq,
                position: (seq != 0).then_some((seq, run)),
            }
        }
    }

    /// An observation as `<run>:<seq>:<me>:<label>@<site>:<a>:<b>`.
    fn observation(seen: Seen) -> String {
        let me = seen
            .me()
            .map_or_else(|| "-".to_string(), |me| me.to_string());
        format!(
            "{}:{}:{me}:{}@{}:{}:{}",
            seen.run(),
            seen.seq(),
            seen.label(),
            seen.site(),
            seen.a(),
            seen.b()
        )
    }

    /// The outcome of a stage.
    enum Outcome {
        Held(Witness),
        Missed(String),
        Unverifiable(String),
        Withheld,
    }

    /// The stages of the card open on this thread. [Stages] is a handle to it, so
    /// the panic hook can evaluate and report them.
    struct State {
        /// The card, or an empty string before the first [Stages::new].
        card: &'static str,
        n: u32,
        /// Whether stage `k` has an outcome, at `k - 1`.
        settled: Vec<bool>,
        /// The stages recorded as held.
        held: u32,
        /// Whether the `truncated` line was printed.
        noticed: bool,
        since: u64,
        open: bool,
        handed_off: bool,
        phase: &'static str,
        /// The stage lines printed so far.
        lines: Vec<String>,
        evaluate: Option<fn(&mut Stages)>,
    }

    impl State {
        const fn new() -> Self {
            Self {
                card: "",
                n: 0,
                settled: Vec::new(),
                held: 0,
                noticed: false,
                since: 0,
                open: false,
                handed_off: false,
                phase: "prefix",
                lines: Vec::new(),
                evaluate: None,
            }
        }
    }

    /// The stages `E1` to `En` of one card.
    #[derive(Debug)]
    pub struct Stages {
        _private: (),
    }

    impl Stages {
        /// Opens the stages of card `card` with `n` History events: watches the
        /// trace, opens the prefix phase and prints `phase prefix`, and installs the
        /// panic hook, once per process.
        pub fn new(card: &'static str, n: u32) -> Self {
            install_hook();
            statelens::watch();
            STATE.with(|state| {
                *state.borrow_mut() = State {
                    card,
                    n,
                    settled: vec![false; n as usize],
                    open: true,
                    ..State::new()
                }
            });
            emit(card, "phase prefix");
            Self { _private: () }
        }

        /// Takes the knobs, so none is picked later, and checks the budget before any
        /// engine starts: `prefix`, the stage deadlines plus the largest release
        /// delay, exceeding `runtime`, the runtime deadline, is a scaffold error.
        pub fn budget(&self, knobs: Knobs, prefix: Duration, runtime: Duration) {
            drop(knobs);
            if prefix > runtime {
                scaffold_error(
                    &card(),
                    format_args!(
                        "budget: the prefix {prefix:?} exceeds the runtime deadline {runtime:?}"
                    ),
                );
            }
        }

        /// Stage `k` held: prints its record, adds its feature, moves
        /// [Stages::since] past its position and returns `true`. Does nothing and
        /// returns `false` for stage n, which only [Stages::handoff] records, for a
        /// stage that has an outcome, for an event number outside 1 to n, and once
        /// the prefix is closed. A witness read at or after the position of the first
        /// observation the trace dropped makes the stage `unverifiable (trace
        /// truncated)` instead, with no feature, and returns `false`.
        pub fn held(&mut self, k: u32, witness: Witness) -> bool {
            settle(k, Outcome::Held(witness), false)
        }

        /// Stage `k` missed, with `detail`, or `cannot: <capability>`. The first miss
        /// closes the prefix, except in the control run, and prints up to 64 trace
        /// lines from the stage's start. A miss after the trace dropped an
        /// observation is `unverifiable (trace truncated)` instead, and closes
        /// nothing, unless it is a `cannot:`. Stage n takes only a `cannot:`, after
        /// which [Stages::handoff] reports the handoff lost.
        pub fn missed(&mut self, k: u32, detail: &str) {
            settle(k, Outcome::Missed(detail.to_string()), false);
        }

        /// Stage `k` is unverifiable, for `reason`: no available witness binds it.
        /// For stage n, call it before [Stages::handoff], which then reports the
        /// handoff lost.
        pub fn unverifiable(&mut self, k: u32, reason: &str) {
            settle(k, Outcome::Unverifiable(reason.to_string()), true);
        }

        /// Stage `k` was withheld: the control run skipped its action.
        pub fn withheld(&mut self, k: u32) {
            settle(k, Outcome::Withheld, false);
        }

        /// Whether the prefix is open.
        pub fn open(&self) -> bool {
            STATE.with(|state| state.borrow().open)
        }

        /// The position from which the next stage reads the trace.
        pub fn since(&self) -> u64 {
            STATE.with(|state| state.borrow().since)
        }

        /// Decides the handoff. Takes a position; then, when stage n has no outcome
        /// and the prefix is open, calls `read`, which must read `En`'s witness and
        /// cannot await; then takes the handoff mark, and records `En` held with the
        /// witness `read` returned, or missed on `None`. The handoff holds when `En`
        /// was held in this call and the mark directly follows the witness's read.
        /// Once the trace dropped an observation at or before the mark, `En` is
        /// `unverifiable (trace truncated)` instead and the handoff is lost. Prints
        /// the handoff, `phase continuation` and the `reach` line, closes the prefix
        /// and stops watching. Does nothing when called again.
        pub fn handoff(&mut self, read: impl FnOnce() -> Option<Witness>) {
            let Some((card, n, pending)) = STATE.with(|state| {
                let state = state.borrow();
                let last = (state.n as usize).checked_sub(1);
                let pending =
                    state.open && last.is_some_and(|last| state.settled.get(last) == Some(&false));
                (!state.handed_off).then_some((state.card, state.n, pending))
            }) else {
                return;
            };
            position();
            let witness = pending.then(read);
            let mark = position();
            let cut = truncation().is_some_and(|seq| seq <= mark);
            let mut evidence = None;
            if let Some(witness) = witness {
                let outcome = match witness {
                    _ if cut => Outcome::Unverifiable(TRUNCATED.to_string()),
                    Some(witness) => {
                        evidence = Some((witness.read, witness.position));
                        Outcome::Held(witness)
                    }
                    None => Outcome::Missed("not held at handoff".to_string()),
                };
                if !settle(n, outcome, true) {
                    evidence = None;
                }
            }
            let holds = evidence.is_some_and(|(read, _)| read != 0 && mark == read + 1);
            // Reading the trace copies it, so `next=` is read only for a line that
            // prints.
            let next = evidence
                .and_then(|(_, position)| position)
                .filter(|_| reach())
                .and_then(|(seq, run)| {
                    statelens::observations(seq.saturating_add(1))
                        .into_iter()
                        .find(|seen| {
                            seen.run() == run
                                && !statelens::is_byzantine(
                                    seen.me().map(statelens::Participant::new),
                                )
                        })
                })
                .map_or_else(
                    || "-".to_string(),
                    |seen| format!("{}:{}", seen.run(), seen.seq()),
                );
            let held = STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.open = false;
                state.handed_off = true;
                state.phase = "continuation";
                state.held
            });
            statelens::unwatch();
            let verdict = if holds { "holds" } else { "lost" };
            emit(card, &format!("handoff {verdict} mark={mark} next={next}"));
            emit(card, "phase continuation");
            emit(
                card,
                &format!("reach {held}/{n} control={}", u8::from(control())),
            );
        }

        /// Shape A: registers the evaluation of the stages, which the panic hook runs
        /// over the trace so far.
        pub fn on_panic(&mut self, evaluate: fn(&mut Self)) {
            STATE.with(|state| state.borrow_mut().evaluate = Some(evaluate));
        }

        /// Prints `done`, after the last oracle.
        pub fn done(&mut self) {
            emit(&card(), "done");
        }
    }

    /// Records the outcome of stage `k`, and returns whether it recorded it held.
    /// `last` lets the handoff, the panic hook and [Stages::unverifiable] record
    /// stage n; a `cannot:` miss records it too. Once the trace dropped an
    /// observation, a miss other than a `cannot:`, and a witness read at or after the
    /// dropped position, are `unverifiable (trace truncated)`.
    fn settle(k: u32, outcome: Outcome, last: bool) -> bool {
        let cut = truncation();
        let outcome = match outcome {
            Outcome::Held(witness) if cut.is_some_and(|seq| witness.read >= seq) => {
                Outcome::Unverifiable(TRUNCATED.to_string())
            }
            Outcome::Missed(text) if cut.is_some() && !text.starts_with("cannot:") => {
                Outcome::Unverifiable(TRUNCATED.to_string())
            }
            outcome => outcome,
        };
        let last = last || matches!(&outcome, Outcome::Missed(text) if text.starts_with("cannot:"));
        let control = control();
        let recorded = STATE.with(|state| {
            let mut state = state.borrow_mut();
            let n = state.n;
            let index = (k as usize).checked_sub(1)?;
            if !state.open || k > n || (k == n && !last) || state.settled.get(index) != Some(&false)
            {
                return None;
            }
            state.settled[index] = true;
            let start = state.since;
            let line = match &outcome {
                Outcome::Held(witness) => {
                    state.held += 1;
                    let next = witness
                        .position
                        .map_or(witness.read, |(seq, _)| seq)
                        .saturating_add(1);
                    state.since = state.since.max(next);
                    format!(
                        "E{k}/{n} held {} bind={} {} read={}",
                        witness.kind, witness.bind, witness.evidence, witness.read
                    )
                }
                Outcome::Missed(text) => {
                    if !control {
                        state.open = false;
                    }
                    with_detail(format!("E{k}/{n} missed"), text)
                }
                Outcome::Unverifiable(text) => with_detail(format!("E{k}/{n} unverifiable"), text),
                Outcome::Withheld => format!("E{k}/{n} withheld"),
            };
            state.lines.push(line.clone());
            Some((state.card, line, start))
        });
        let Some((card, line, start)) = recorded else {
            return false;
        };
        emit(card, &line);
        match outcome {
            Outcome::Held(_) => {
                feature(card, k);
                true
            }
            Outcome::Missed(_) => {
                // Reading the trace copies it, so it is read only for lines that print.
                if reach() {
                    for seen in statelens::observations(start).into_iter().take(TRACE_LINES) {
                        emit(card, &format!("trace {}", observation(seen)));
                    }
                }
                false
            }
            Outcome::Unverifiable(_) | Outcome::Withheld => false,
        }
    }

    /// `head`, then `text` as the rest of the line when there is one.
    fn with_detail(head: String, text: &str) -> String {
        if text.is_empty() {
            head
        } else {
            format!("{head} {}", field_detail(text))
        }
    }

    /// Chains the helper's panic hook in front of the current one (libFuzzer's),
    /// once per process.
    fn install_hook() {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                report_panic(info);
                previous(info);
            }));
        });
    }

    /// Prints the `panic` line, the phase and the stage lines so far; in Shape A, the
    /// stages the registered evaluation finds in the trace; and `unverifiable
    /// (crashed)` for every stage of the open prefix the hook cannot read.
    fn report_panic(info: &std::panic::PanicHookInfo<'_>) {
        if !reach() {
            return;
        }
        let Some((card, phase, lines, evaluate)) = STATE.with(|state| {
            let state = state.try_borrow().ok()?;
            (!state.card.is_empty()).then(|| {
                (
                    state.card,
                    state.phase,
                    state.lines.clone(),
                    state.evaluate.filter(|_| !state.handed_off),
                )
            })
        }) else {
            return;
        };
        let location = info.location().map_or_else(
            || "-".to_string(),
            |location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            },
        );
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("Box<dyn Any>");
        let first = message.lines().next().unwrap_or("");
        emit(card, &with_detail(format!("panic {location}"), first));
        emit(card, &format!("phase {phase}"));
        for line in &lines {
            emit(card, line);
        }
        let mut stages = Stages { _private: () };
        if let Some(evaluate) = evaluate {
            evaluate(&mut stages);
        }
        let n = STATE.with(|state| {
            state
                .try_borrow()
                .ok()
                .filter(|state| !state.handed_off)
                .map_or(0, |state| state.n)
        });
        for k in 1..=n {
            settle(k, Outcome::Unverifiable("(crashed)".to_string()), true);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        thread_local! {
            /// The lines the helper printed on this thread, without their prefix and card.
            pub(super) static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
            /// The stages whose feature the helper added on this thread.
            pub(super) static FEATURES: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
        }

        /// Opens `n` stages of `card` with no knobs, forgetting what earlier tests on
        /// this thread printed.
        fn open(card: &'static str, n: u32) -> Stages {
            LINES.take();
            FEATURES.take();
            let knobs = Knobs::split(card, &mut Vec::new(), 0);
            let stages = Stages::new(card, n);
            stages.budget(knobs, Duration::ZERO, Duration::ZERO);
            stages
        }

        /// Notes `count` observations of replica 0 in state `a`, as a probe would.
        fn observe(a: u32, count: usize) {
            for _ in 0..count {
                let me = Some(statelens::Participant::new(0));
                statelens::note(me, "state", "state.rs:1:1", a, 0);
            }
        }

        /// The observation at position `seq`.
        fn at(seq: u64) -> Seen {
            let found = statelens::observations(seq);
            assert_eq!(found.first().map(|seen| seen.seq()), Some(seq));
            found[0]
        }

        /// The index of the first of `lines` that starts with `start`.
        fn find(lines: &[String], start: &str) -> Option<usize> {
            lines.iter().position(|line| line.starts_with(start))
        }

        #[test]
        fn test_stages_read_after_the_cut_are_unverifiable() {
            let mut stages = open("TS-9001", 3);
            observe(1, 1);
            let first = at(statelens::mark());
            assert!(
                stages.held(1, Witness::intrinsic("R=0@E1", first)),
                "a stage read before the cut holds"
            );
            observe(1, statelens::TRACE_CAP - 1);
            assert_eq!(statelens::truncated(), None, "the trace is full, not cut");
            let kept = statelens::mark();
            observe(0, 1);
            let cut = statelens::truncated().expect("the trace drops the state change");
            assert_eq!(cut, kept + 1);
            let stale = at(kept);
            assert_eq!(stale.a(), 1, "the latest observation kept is stale");
            assert!(
                !stages.held(2, Witness::intrinsic("R=0@E2", stale)),
                "a stage read after the cut does not hold"
            );
            stages.handoff(|| Some(Witness::intrinsic("R=0@E3", stale)));
            let lines = LINES.take();
            assert_eq!(lines.len(), 8, "{lines:#?}");
            assert_eq!(lines[0], "phase prefix");
            assert!(lines[1].starts_with("E1/3 held intrinsic bind=R=0@E1 obs="));
            assert_eq!(lines[2], format!("truncated seq={cut}"));
            assert_eq!(lines[3], "E2/3 unverifiable (trace truncated)");
            assert_eq!(lines[4], "E3/3 unverifiable (trace truncated)");
            assert!(lines[5].starts_with("handoff lost mark="), "{}", lines[5]);
            assert_eq!(lines[6], "phase continuation");
            assert_eq!(lines[7], "reach 1/3 control=0");
            assert_eq!(FEATURES.take(), vec![1], "none for a stage after the cut");
            assert_eq!(statelens::truncated(), None, "the handoff stops watching");
        }

        #[test]
        fn test_handoff_cannot_hold_across_a_cut() {
            let mut stages = open("TS-9002", 2);
            observe(1, 1);
            let first = at(statelens::mark());
            assert!(stages.held(1, Witness::intrinsic("R=0@E1", first)));
            observe(1, statelens::TRACE_CAP - 1);
            let kept = statelens::mark();
            let mut cut = None;
            stages.handoff(|| {
                let witness = Witness::intrinsic("R=0@E2", at(kept));
                // The state changes between the read and the mark, past the cap.
                observe(0, 1);
                cut = statelens::truncated();
                Some(witness)
            });
            let cut = cut.expect("the trace drops the state change");
            let lines = LINES.take();
            let truncated = find(&lines, "truncated").expect("the cut is printed");
            assert_eq!(lines[truncated], format!("truncated seq={cut}"));
            assert_eq!(find(&lines[truncated + 1..], "truncated"), None, "once");
            let last = find(&lines, "E2/2").expect("En has a line");
            assert!(truncated < last, "{lines:#?}");
            assert_eq!(lines[last], "E2/2 unverifiable (trace truncated)");
            assert!(lines[last + 1].starts_with("handoff lost mark="));
            assert!(find(&lines, "reach 1/2 control=0").is_some());
            assert_eq!(FEATURES.take(), vec![1]);
        }

        #[test]
        fn test_handoff_holds_without_a_cut() {
            let mut stages = open("TS-9003", 2);
            observe(1, 1);
            let first = at(statelens::mark());
            assert!(stages.held(1, Witness::intrinsic("R=0@E1", first)));
            observe(1, 1);
            let last = statelens::mark();
            stages.handoff(|| Some(Witness::intrinsic("R=0@E2", at(last))));
            let lines = LINES.take();
            assert_eq!(find(&lines, "truncated"), None);
            let last = find(&lines, "E2/2 held intrinsic").expect("En holds");
            assert!(lines[last + 1].starts_with("handoff holds mark="));
            assert!(find(&lines, "reach 2/2 control=0").is_some());
            assert_eq!(FEATURES.take(), vec![1, 2]);
        }

        #[test]
        fn test_unverifiable_last_stage_loses_the_handoff() {
            let mut stages = open("TS-9004", 2);
            observe(1, 1);
            let first = at(statelens::mark());
            assert!(stages.held(1, Witness::intrinsic("R=0@E1", first)));
            stages.unverifiable(2, "no observable binds v");
            stages.handoff(|| unreachable!("En has an outcome"));
            let lines = LINES.take();
            let last = find(&lines, "E2/2").expect("En has a line");
            assert_eq!(lines[last], "E2/2 unverifiable no observable binds v");
            assert!(
                lines[last + 1].starts_with("handoff lost mark="),
                "{lines:#?}"
            );
            assert!(find(&lines, "reach 1/2 control=0").is_some(), "{lines:#?}");
            assert_eq!(FEATURES.take(), vec![1]);
        }

        #[test]
        fn test_lines_that_do_not_print_read_no_trace() {
            let mut stages = open("TS-9005", 2);
            observe(1, 2);
            stages.missed(1, "deadline");
            let lines = LINES.take();
            let traced = lines
                .iter()
                .filter(|line| line.starts_with("trace "))
                .count();
            assert_eq!(traced, if reach() { 2 } else { 0 }, "{lines:#?}");
            let mut stages = open("TS-9005", 1);
            observe(1, 1);
            let last = statelens::mark();
            observe(1, 1);
            stages.handoff(|| Some(Witness::intrinsic("R=0@E1", at(last))));
            let lines = LINES.take();
            let handoff = find(&lines, "handoff holds mark=").expect("the handoff holds");
            assert_eq!(lines[handoff].ends_with(" next=-"), !reach(), "{lines:#?}");
        }
    }
}
