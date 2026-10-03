## Task: audit the bindings of invariants {{INVARIANT_IDS}} of the {{REGISTRY}} registry

These invariants were bound earlier in this campaign, and `{{PLAN}}` records what was done.
Your job is to find the bindings that claim more coverage than they have, and to close the
gap where it can be closed. You are still the instrumenter: every rule above applies,
including "add, never remove".

A campaign that never panics is read as evidence that the bound invariants hold. That
reading is worth exactly as much as the sites the checks sit on, and nothing more. A check
in the wrong place is silent for the same reason a correct implementation is.

For each invariant below:

1. Read the Statement again, from the registry file printed below, not from the plan's
   `Reading`. A binding goes wrong where the reading went wrong, so re-derive `pre` and
   `post` before you look at what was instrumented.
2. Name every action the Statement constrains, and find the commit site of each one: the
   point past which the act is visible outside the replica (a signature exists, a message
   is handed to a mailbox or to the broadcaster, a record is appended to the journal, a
   certificate is accepted, the view counter moves). Find them with the code tools, from
   the root of the repository and with `SL=consensus/fuzz/statelens/scripts/statelens.py`:
   `python3 $SL code refs|callers|callees <NAME>` and `python3 $SL ast sites <NAME>`.
   Include the paths that are easy to miss: journal replay, retries and rebroadcasts, and
   the handler that acts on the reply to a request the replica sent earlier. The guide
   `consensus/fuzz/statelens/prompts/discover-flow.md` is the method when this is not
   enough; its step 6 is about following a request to where it lands.
3. Compare that list with what is instrumented. `rg "\[statelens\] INV-NNNN" consensus/src`
   gives the sites of one invariant. Mark each commit site `checked` or `not checked`. A
   check that runs where the action is decided, while the act happens in a later handler,
   leaves that site `not checked`: between the two the replica handles messages, and the
   state the check read is not the state it acted on.
4. Close each gap you can. Add the same condition the binding already checks, re-read at
   that site, with the replica's own index, under the rules above. Ghost state in another
   module is reachable: add a read-only accessor beside the field. If the commit site needs
   a tolerance the first site did not -- a guard there made the condition safe, and here
   there is none -- close the gap with that tolerance and name it in the Notes; that is a
   close, not a strengthening. Where the site cannot carry the check at all -- no
   participant identity anywhere in scope, or the site is outside the editable code -- add
   nothing and record why.
5. Check the other direction for each existing assertion: can its `pre` be true where it
   stands? If a guard just above returns for exactly the state the Statement forbids, or
   the condition restates the line above it, that assertion checks nothing. Add a check
   where the forbidden state survives if there is such a site, and say so in the Notes
   either way. Leave the original in place; you may add, never remove. Ask the same of the
   feedback: an assertion whose recorded pair cannot vary on a passing execution -- a
   `post` of `false`, or a site on the branch taken only once the replica is about to
   violate the invariant -- gives the fuzzer nothing, so add the classification probe of
   rule 6.
6. Update the invariant's section of the plan: the `Sites` ledger, the `Assertions` you
   added, a `Status` that matches the ledger under the rule of the binding task (`bound`
   only when every commit site is checked and the condition is the Statement itself), and
   Notes that name, for each unchecked site, the delivery order that escapes it. Downgrade
   a status whose claim you could not support. Do not raise one without having added the
   checks that justify it. Each entry gives the file and the function, and the ledger is
   checked against the code: an entry you call `checked` must carry an assertion naming
   this invariant in the file it names, so an unchecked site recorded as checked is a
   false record, not a shortcut.
7. Check what each binding costs where it runs. A check that filters or walks a ghost
   history is unbounded, because that history outlives the implementation's pruning: add
   the index the question needs, maintain it where the history is written, and use it.
   This is one of the two things you may change in instrumentation an earlier pass added;
   the other is an assertion that is wrong. "Add, never remove" is about the
   implementation's own code, not about a previous pass's instrumentation.
8. Change nothing else. Do not rewrite a faithful binding because you would have written it
   differently, do not strengthen a condition to make a status look better, and do not
   touch the sites of an invariant that is not in this batch. Beacon probes come in a
   later step; leave the beacon table of the plan alone.

Run the check command until it passes. Then run

    python3 consensus/fuzz/statelens/scripts/statelens.py lint-plan

and fix what it reports about the invariants of this batch. It reads the ledger against the
code, so it catches a site recorded as checked that asserts nothing, an entry that gives no
verdict, and a `bound` that the ledger does not support. What it cannot catch is a commit
site the ledger never names, which is the part only you can do.

Reply with one line per invariant: the id, the status before and after, the sites you added,
and the gaps you left.

Invariants:

{{INVARIANTS}}
