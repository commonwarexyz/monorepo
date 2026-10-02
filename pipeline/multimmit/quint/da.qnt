// The chain layer of Multimmit as a state machine: block production,
// DA-voting, and DA-certificate formation.
//
// This layer never waits on consensus. Producers extend their own chains
// continuously, everyone DA-votes whatever arrives, and producers turn D
// DA-votes into certificates -- none of which reads a view, a leader
// block or a vote. The dependence runs one way only, and the consensus
// layer's entire view of this module is two monotone variables:
//
//     da_voted      -- read by Positions and Extensions when voting,
//     store_da_cert -- read by ProposeChains when choosing an anchor.
//
// Nothing in the consensus layer reads `produced`. That is the point of
// the split: a voter reports what it holds rather than fetching what it
// lacks, so no processor blocks or fetches on the critical path.
//
// The plan for this module was to start with an abstract oracle growing
// da_voted and store_da_cert subject to the invariants the concrete
// rules establish (C1: one DA-vote per (chain, height); C2: certified
// blocks compatible; C5: DA-voting implies holding the path). The
// concrete rules are written here instead, for two reasons: they are
// barely longer, and they constrain the state space rather than opening
// it, so they are both cheaper to check and more faithful. C1, C2 and C5
// then become genuine checks of the rules rather than restatements of
// the oracle's guard.

module da {
    import types.* from "./types"
    import option.* from "./option"
    import blocks.* from "./blocks"
    import defs.* from "./defs"

    // -------------------------------------------------
    // Parameters
    // -------------------------------------------------

    // Correct-style actors: correct replicas and twins.
    // Byzantine actors are modelled separately and share nothing but
    // keys with these.
    const DA_REPLICA_IDS: Set[ReplicaId]
    const DA_BYZANTINE: Set[ReplicaId]
    const DA_REPLICA_KEYS: ReplicaId -> ReplicaKey
    // Chain ownership: chain i belongs to processor p_i, and only p_i
    // may produce blocks on it (blocks are signed by their producer).
    const DA_CHAIN_OF: ReplicaId -> ChainId
    // The payloads available to producers, and the greatest height any
    // chain may reach: the two bounds that make the model finite.
    const DA_PAYLOADS: Set[PayloadId]
    const DA_MAX_HEIGHT: int
    const DA_PARAMS: Params

    // Derived, not given: the paper indexes chains 1..n, one per
    // processor. See the note on CHAINS in consensus.qnt.
    pure val DA_CHAINS: Set[ChainId] = 1.to(DA_PARAMS.n)

    pure def da_sig_of(id: ReplicaId): ReplicaKey = DA_REPLICA_KEYS.get(id)

    pure val DA_FAULTY_KEYS = DA_BYZANTINE.map(id => da_sig_of(id))

    // -------------------------------------------------
    // State
    // -------------------------------------------------

    // The blocks that have been produced, i.e. signed by the owner of
    // their chain. Nothing outside this module reads it: a chain
    // proposal may name blocks that were never produced (junk), and
    // correct voters report a lower position for them.
    var produced: Set[Block]

    // The DA-voting history of each correct-style actor: the blocks it
    // has sent a DA-vote for. One of the two variables the consensus
    // layer reads.
    var da_voted: ReplicaId -> Set[Block]

    // DA-certificates that have been broadcast, and the ones each actor
    // has received. The other variable the consensus layer reads.
    var sent_da_cert: Set[DACert]
    var store_da_cert: ReplicaId -> Set[DACert]

    // -------------------------------------------------
    // The DA-voting rule (the paper's DA-voting conditions)
    // -------------------------------------------------

    // The greatest height < h at which `certs` holds a certificate for
    // chain i. Genesis blocks are considered DA-certified at the start
    // of the execution, so the fold starts -- and in the absence of any
    // other certificate ends -- at height 0.
    pure def greatest_cert_below(certs: Set[DACert], i: ChainId, h: Height): Height = {
        certs.fold(0, (acc, c) =>
            if (c.block.chain == i and block_height(c.block) < h)
                max(acc, block_height(c.block))
            else
                acc)
    }

    // The certified block of chain i at that height (the genesis block
    // when the height is 0). Unique by C2: two certificates at one
    // height on one chain certify compatible, hence equal, blocks.
    pure def cert_block_at(certs: Set[DACert], i: ChainId, h: Height): Block = {
        certs.fold(genesis_block(i), (acc, c) =>
            if (c.block.chain == i and block_height(c.block) == h)
                c.block
            else
                acc)
    }

    // May `r` DA-vote for the transaction block b?
    //
    //  (0) b is correctly signed and syntactically well-formed -- here,
    //      b has been produced by the owner of its chain;
    //  (i) at most one DA-vote per (chain, height);
    //  (ii) the pipelining window: a producer may run up to d blocks
    //       ahead of its last certified block;
    //  (iii) r holds the whole path from the certified block up to b,
    //        and has DA-voted every block on that path below b.
    //
    // Conditions (i) and (iii) together are what make all DA-certified
    // blocks on a chain compatible; (ii) bounds the uncertified head of
    // a chain at d blocks.
    pure def may_da_vote(
        voted: Set[Block],
        certs: Set[DACert],
        b: Block,
        produced_blocks: Set[Block],
        p: Params
    ): bool = {
        val i = b.chain
        val h = block_height(b)
        val h_prime = greatest_cert_below(certs, i, h)
        val anchor = cert_block_at(certs, i, h_prime)
        and {
            // (0)
            produced_blocks.contains(b),
            h >= 1,
            // (i)
            not(voted.exists(bb => bb.chain == i and block_height(bb) == h)),
            // (ii)
            h - h_prime <= p.d,
            // (iii): the path from the certified anchor up to b, with
            // every block on it strictly below b already DA-voted.
            //
            // The heights are sieved out of the fixed range
            // 1..DA_MAX_HEIGHT rather than built as (h_prime+1).to(h-1):
            // a range whose bounds are not literals is beyond Apalache,
            // whereas a filter over a constant range is not. Every height
            // strictly between h_prime and h lies in 1..DA_MAX_HEIGHT,
            // since h_prime >= 0 and h <= DA_MAX_HEIGHT for any block the
            // state machine builds, so the two agree.
            b.does_extend_block(anchor),
            1.to(DA_MAX_HEIGHT)
                .filter(hh => h_prime < hh and hh < h)
                .forall(hh => voted.contains(ancestor_at(b, hh))),
        }
    }

    // The keys that have DA-voted for b, among the correct-style actors.
    // Counted over keys, not actors: twins share a key and contribute
    // one DA-vote share, not two.
    def da_voters(b: Block): Set[Signature] = {
        DA_REPLICA_IDS.filter(id => da_voted.get(id).contains(b)).map(id => da_sig_of(id))
    }

    // -------------------------------------------------
    // Actions
    // -------------------------------------------------

    action da_init: bool = all {
        produced' = DA_CHAINS.map(i => genesis_block(i)),
        da_voted' = DA_REPLICA_IDS.mapBy(_ => Set()),
        sent_da_cert' = Set(),
        store_da_cert' = DA_REPLICA_IDS.mapBy(_ => Set()),
    }

    action da_unchanged: bool = all {
        produced' = produced,
        da_voted' = da_voted,
        sent_da_cert' = sent_da_cert,
        store_da_cert' = store_da_cert,
    }

    // A correct producer extends its own chain by one block. It never
    // equivocates: it produces at most one child of any block, so its
    // chain stays a path rather than a tree.
    action da_produce(id: ReplicaId, parent: Block, payload: PayloadId): bool = all {
        val i = DA_CHAIN_OF.get(id)
        val nb = { chain: i, payloads: parent.payloads.append(payload) }
        all {
            parent.chain == i,
            or { produced.contains(parent), parent == genesis_block(i) },
            block_height(nb) <= DA_MAX_HEIGHT,
            // no equivocation: no other child of `parent` exists already
            not(produced.exists(b => and {
                b.chain == i,
                block_height(b) == block_height(nb),
                b.does_extend_block(parent),
                b != nb,
            })),
            produced' = produced.union(Set(nb)),
            da_voted' = da_voted,
            sent_da_cert' = sent_da_cert,
            store_da_cert' = store_da_cert,
        }
    }

    // A faulty producer may produce ANY block on its own chain, at any
    // height within the bound -- in particular two incompatible blocks
    // at one height. It cannot produce on another processor's chain:
    // blocks are signed by their producer.
    action da_byz_produce(b: Block): bool = all {
        DA_BYZANTINE.exists(id => DA_CHAIN_OF.get(id) == b.chain),
        block_height(b) >= 1,
        block_height(b) <= DA_MAX_HEIGHT,
        b.payloads.indices().forall(j => DA_PAYLOADS.contains(b.payloads[j])),
        produced' = produced.union(Set(b)),
        da_voted' = da_voted,
        sent_da_cert' = sent_da_cert,
        store_da_cert' = store_da_cert,
    }

    // A correct-style actor DA-votes for a block, if the DA-voting rule
    // permits. A block may be DA-voted however it was received -- by
    // relay is as good as direct -- so there is no delivery step here.
    action da_vote_step(id: ReplicaId, b: Block): bool = all {
        may_da_vote(da_voted.get(id), store_da_cert.get(id), b, produced, DA_PARAMS),
        da_voted' = da_voted.set(id, da_voted.get(id).union(Set(b))),
        produced' = produced,
        sent_da_cert' = sent_da_cert,
        store_da_cert' = store_da_cert,
    }

    // Form and broadcast a DA-certificate for b once D keys have
    // DA-voted it. The adversary may pad the signature
    // set with the keys it controls: a faulty key contributes a share
    // whether or not the modelled actor "sent" one.
    action da_certify_step(b: Block): bool = all {
        nondet extra = DA_FAULTY_KEYS.powerset().oneOf()
        val sigs = da_voters(b).union(extra)
        all {
            sigs.size() >= da_quorum(DA_PARAMS),
            sent_da_cert' = sent_da_cert.union(Set(da_cert(b, sigs, "DA"))),
            produced' = produced,
            da_voted' = da_voted,
            store_da_cert' = store_da_cert,
        }
    }

    // Receive a broadcast certificate.
    action da_deliver_cert(id: ReplicaId, c: DACert): bool = all {
        sent_da_cert.contains(c),
        store_da_cert' = store_da_cert.set(id, store_da_cert.get(id).union(Set(c))),
        produced' = produced,
        da_voted' = da_voted,
        sent_da_cert' = sent_da_cert,
    }

    // One step of the chain layer.
    action da_step: bool = any {
        all {
            nondet id = oneOf(DA_REPLICA_IDS)
            nondet payload = oneOf(DA_PAYLOADS)
            nondet parent = oneOf(produced.union(DA_CHAINS.map(i => genesis_block(i))))
            da_produce(id, parent, payload),
        },
        all {
            DA_BYZANTINE != Set(),
            nondet b = oneOf(all_candidate_blocks)
            da_byz_produce(b),
        },
        all {
            nondet id = oneOf(DA_REPLICA_IDS)
            nondet b = oneOf(produced)
            da_vote_step(id, b),
        },
        all {
            nondet b = oneOf(produced)
            da_certify_step(b),
        },
        all {
            sent_da_cert != Set(),
            nondet id = oneOf(DA_REPLICA_IDS)
            nondet c = oneOf(sent_da_cert)
            da_deliver_cert(id, c),
        },
    }

    // The blocks a faulty producer may conjure: every path of payloads
    // on a faulty processor's own chain, up to the height bound. Built
    // by iterated extension rather than by enumerating lists, and kept
    // small by DA_PAYLOADS and DA_MAX_HEIGHT -- this set is the main
    // lever on the size of the chain layer's state space.
    pure val all_candidate_blocks: Set[Block] = {
        val faulty_chains = DA_BYZANTINE.map(id => DA_CHAIN_OF.get(id))
        1.to(DA_MAX_HEIGHT).fold(
            faulty_chains.map(i => genesis_block(i)),
            (acc, _) => acc.union(acc.fold(Set(), (a, b) =>
                if (block_height(b) >= DA_MAX_HEIGHT)
                    a
                else
                    a.union(DA_PAYLOADS.map(pl =>
                        { chain: b.chain, payloads: b.payloads.append(pl) })))))
    }

    // -------------------------------------------------
    // Chain-layer invariants
    // -------------------------------------------------

    // C1 -- a correct replica DA-votes at most once per (chain, height).
    val c1_one_da_vote_per_height = DA_REPLICA_IDS.forall(id => {
        val voted = da_voted.get(id)
        tuples(voted, voted).forall(((b1, b2)) =>
            (b1.chain == b2.chain and block_height(b1) == block_height(b2)) implies b1 == b2)
    })

    // C2 -- any two DA-certified blocks on one chain are compatible.
    // Two D-sets intersect in 2D - n = n - 4f >= f + 1 replicas, hence
    // in a correct one, which DA-votes at most once per (chain, height).
    val c2_certified_blocks_compatible = {
        val certified = sent_da_cert.map(c => c.block)
        tuples(certified, certified).forall(((b1, b2)) =>
            b1.chain != b2.chain or not(incompatible(b1, b2)))
    }

    // C5 -- DA-voting implies possession: a correct replica that
    // DA-voted b holds every block on the path from its certifiable
    // anchor up to b, and DA-voted each of them below b. Here: every
    // ancestor of b above the greatest certified height is itself
    // DA-voted.
    val c5_da_vote_implies_path = DA_REPLICA_IDS.forall(id => {
        val voted = da_voted.get(id)
        voted.forall(b => {
            val h_prime = greatest_cert_below(store_da_cert.get(id), b.chain, block_height(b))
            (h_prime + 1).to(block_height(b) - 1).forall(hh => voted.contains(ancestor_at(b, hh)))
        })
    })

    // Every DA-certificate carries at least D signatures.
    val da_certs_wellformed = sent_da_cert.forall(c => da_cert_wellformed(c, DA_PARAMS))

    val da_invariants = all {
        c1_one_da_vote_per_height,
        c2_certified_blocks_compatible,
        c5_da_vote_implies_path,
        da_certs_wellformed,
    }
}
