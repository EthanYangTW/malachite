# Runtime Test Plan: Finding 1 (unauthenticated future-height input flood)

Companion to `SECURITY_FINDINGS.md`. The existing PoC (`poc_future_height_buffer.rs`) drives the
core `State` directly and proves hops 4–5 of the attack path. This plan proves hops 1–3 over the
wire, measures the real memory and liveness impact on running nodes, and gives regression tests
to validate a fix.

## 1. Hypotheses under test

| ID | Claim | Proven by |
|----|-------|-----------|
| H1 | A peer with no validator key, connected over libp2p only, can deliver an arbitrary 4 MiB `Vote` for `height+1` to a running node's consensus actor. | T1, T3 |
| H2 | The receiving node relays that message to its other gossipsub peers before any consensus-level validation (amplification). | T2 |
| H3 | A running node retains up to `queue_per_height_capacity` (500) such votes per future height, bounded by count only; RSS grows accordingly. | T3 |
| H4 | Once a height's slots are full, a legitimate early proposal/vote for that height is dropped and never reaches consensus; the node loses round 0 of that height. | T4 |
| H5 | The same flood addressed to the **current** height is rejected (negative control: the height gate is the defect, not signature verification). | T5 |
| H6 | The default configuration does not mitigate (no per-topic size limit, peer scoring off, no message validation reporting). | T2, T3 |

## 2. Test tiers and harnesses

| Tier | Harness | Scope | Where |
|------|---------|-------|-------|
| A | `crates/network/test` (raw `malachitebft_network::spawn` + `CtrlHandle`) | Hops 1–3: delivery and relay of an oversized, unsigned-by-validator vote | new file `crates/network/test/tests/future_height_flood.rs` |
| B | `crates/test/framework` (`TestBuilder`, full test-app nodes) plus a standalone **injector** peer built from `malachitebft_network::spawn` | Hops 1–5 end to end: buffer growth, dropped legitimate proposal, round loss | new file `crates/test/tests/it/future_height_flood.rs` |
| C | Manual / CI-optional: 4 test-app processes on loopback + injector binary, RSS sampled with `ps`/`/proc` | Absolute memory figures at wire-max (4 MiB) sizes | script under `scripts/` (not run in unit CI) |

Templates to copy from:

- Raw peer setup, dialing, publishing and "no relay" assertions: `crates/network/test/tests/pubsub_topic_limits.rs` (`make_config`, `wait_for_peers`, `receive_message`, `assert_no_message`).
- Full-node test with event hooks: `crates/test/tests/it/wal.rs`, `vote_rebroadcast.rs`.
- Node port scheme (to let the injector dial framework nodes): `crates/test/app/src/node.rs:572-630` (`make_config`).

## 3. Common building blocks

### 3.1 Crafting the payload

Use the test context codec so bytes are exactly what the victim decodes
(`crates/test/src/codec/proto/mod.rs`):

```rust
let ext = SignedMessage::new(Bytes::from(vec![0u8; EXT_LEN]), Signature::test());   // 1–4 MiB
let vote = Vote::new_prevote(Height::new(h), Round::new(i), NilOrVal::Val(ValueId::new(1)), attacker_addr)
    .extend(ext);                                     // prevote + extension: illegal at current height
let msg  = SignedConsensusMsg::Vote(SignedVote::new(vote, Signature::test()));      // garbage signature
let bytes = ProtobufCodec.encode(&msg)?;              // <= pubsub_max_size (4 MiB)
```

Vary `round` (or the address byte) per message so gossipsub's message-id dedup does not collapse
the flood. `attacker_addr` must **not** be in the validator set.

### 3.2 Injector peer

```rust
let handle = malachitebft_network::spawn(NetworkIdentity::new(keypair), config, registry).await?;
let (mut rx, ctrl) = handle.split();
// config.persistent_peers = [victim listen addr]; discovery disabled; pubsub GossipSub
wait_for_peers(&mut rx, &[victim_peer_id]).await;
for i in 0..N { ctrl.publish(Channel::Consensus, payload(i)).await?; }
```

The injector never subscribes to anything but the consensus topic and never sends a validator proof.

### 3.3 Observation points on a victim node

| Signal | Source | Use |
|--------|--------|-----|
| `malachitebft_consensus_queue_size`, `queue_heights` | metrics endpoint (`config.metrics.listen_addr`, served by `metrics::serve` in `test/app/src/node.rs:461`) | buffer occupancy (H3) |
| `dropped_buffered_messages{reason}` | same | only counts the pre-`Running` buffer; expect **0** here, which itself shows the drop is silent |
| `Event::Received(SignedConsensusMsg::Vote)` | `TestNode::on_event` | count junk votes reaching the consensus actor (H1) |
| `Event::ReceivedProposedValue`, `Event::StartedRound(h, r, ..)` | `on_event` | whether height `h` started at round 0 or needed round 1+ (H4) |
| "Received vote for higher height, queuing for later" / "Per-key capacity reached, rejecting value" | `debug!` logs (`handle/vote.rs:41`, `bounded_queue.rs:44`) | corroboration |
| process RSS | `/proc/<pid>/status` (Tier C) | H3 absolute |

## 4. Test cases

### T1 (Tier A): oversized non-validator vote is delivered to the application layer

Setup: `sender` (injector) → `victim` (raw network handle, subscribed to `Channel::Consensus`).
Steps: publish one 4 MiB-minus-overhead vote payload.
Assert: `victim` receives `Event::ConsensusMessage(Channel::Consensus, sender, Some(sender), data)` with `data.len()` ≈ 4 MiB within 5 s. (Proves the wire limit, not the content, is the only gate.)

### T2 (Tier A): the message is relayed without validation

Setup: `sender` → `relay` → `observer`, where `observer` is connected only to `relay` (copy of the topology in `pubsub_topic_limits.rs`).
Steps: publish 20 distinct junk votes from `sender`.
Assert: `observer` receives all 20 on `Channel::Consensus` with `published_by == sender`. Repeat with `enable_peer_scoring = true` and show the result is unchanged (no `report_message_validation_result` exists to penalise).

### T3 (Tier B): buffer fills on running validators; no verification happens

Setup: 3 validator nodes (`TestBuilder`, `ProposalAndParts`, `stable_block_times`), injector dials node 0 only.
Steps:
1. Wait until all nodes reach height 2.
2. From the injector, publish 600 votes for height **50** (far enough ahead that no node reaches it during the test), 1 MiB extension each (≈ 600 MiB on the wire; adjust `EXT_LEN` down for constrained CI).
3. Poll each node's metrics every 500 ms for 30 s.
Assert (each node, including nodes 1 and 2 that the injector never dialed):
- `queue_size` reaches **500** and `queue_heights` ≥ 1 (relay confirmed, cap is count-only).
- No `Event::Received` for those votes is followed by any `Published` vote at height 50 and no WAL entry (nodes keep deciding heights 3, 4, … normally in the meantime).
- RSS of each node process grows by ≥ 400 MiB relative to the pre-flood baseline (Tier C gives the exact figure; in Tier B just assert a lower bound via `/proc/self/status` read from the test, or skip on non-Linux).
Pass criterion for the finding: all three nodes show ≥ 500 queued entries from a single unauthenticated peer.

### T4 (Tier B): legitimate next-height proposal is dropped and the height loses round 0

Setup: 4 validators with voting power 10/10/10/70 so node 3 is proposer for most rounds; `target_time` **unset**; node 3 is the only node the injector dials.
Steps:
1. Hook `on_event` on node 0 to record `StartedHeight(h, _)`.
2. When node 0 reports `StartedHeight(H)`, the injector immediately publishes 500 junk votes for `H+1` (small 64-byte extensions suffice here, this test is about count).
3. Let the network run to `H+3`.
Assert on node 0 (and 1, 2):
- `Event::StartedRound(H+1, Round(0), ..)` is followed by `StartedRound(H+1, Round(1), ..)` (round 0 lost) **or** `ReceivedProposedValue` for `H+1` arrives only after `StartedRound(H+1, 1)`.
- Compare against a control run without the injector: `H+1` decides at round 0.
- The node's `debug` log contains "Per-key capacity reached, rejecting value" for the proposal (`Input::Proposal`) at `H+1`.
Note: the window is the inter-node skew between finishing `H` and starting `H+1`. If the skew is too small to catch deterministically, delay node 0 with `start_after`/`restart_after` or use `ByzantineConfig::with_drop_inbound_proposals` on node 0 for height `H` so it decides `H` via a later round than its peers; the proposer then publishes `H+1`'s proposal while node 0 is still at `H`.

### T5 (Tier B, negative control): same flood at the current height is rejected

Steps: identical to T3 but votes target the nodes' **current** height.
Assert: `queue_size` stays 0; victims log "Received vote from unknown validator" (`handle/vote.rs`, in `verify_signed_vote`); WAL append count unchanged. This isolates the height gate as the defect.

### T6 (Tier A/B): `Liveness` topic is an equivalent entry point

Repeat T1 and T3 with `Channel::Liveness` and `LivenessMsg::Vote(..)` encoding. Expect identical results (`engine/src/network.rs:449-468`).

### T7 (Tier C, optional): wire-maximum memory figure

Four test-app processes on loopback with default config (`pubsub_max_size = 4 MiB`, queue 10×500), injector publishes 500 × ~4 MiB votes for each of heights `h+1..h+4` (≈ 8 GiB on the wire). Sample RSS of each process every second. Expected: ≥ 2 GiB growth per flooded height on **every** node; abort when the host has < 2 GiB free. Run under `systemd-run -p MemoryMax=…` or a cgroup so the host is not taken down; record whether the kernel OOM-kills the node (the production outcome).

## 5. Regression tests to add with the fix

| Fix item (see findings §Recommended fix) | Test |
|------------------------------------------|------|
| Byte budget on `BoundedQueue` | unit: pushing entries whose total encoded size exceeds the budget returns `false`; existing count tests still pass |
| Structural rejection before buffering (prevote/nil-precommit with extension, extension > max) | core-consensus integration test modelled on `poc_future_height_buffer.rs`: `queue_size` stays 0, no `WalAppend` |
| Validator-set membership before buffering | same harness: vote from unknown address for `height+1` is dropped; vote from a known validator is still buffered |
| Per-sender cap | Tier B: one injector cannot exceed its cap on any node while two honest nodes' early messages are retained |
| Gossipsub validation reporting | T2 inverted: `observer` receives **nothing** and `sender` is penalised / disconnected |
| Per-topic consensus size default | T1 inverted: a 4 MiB consensus message is refused at the relay (reuse `assert_no_message`) |

## 6. Execution

```bash
cd code
# Tier A
cargo nextest run -p arc-malachitebft-network-test -E 'test(future_height_flood)'
# Tier B (large; run serially, needs ~1–2 GiB free)
cargo nextest run -p arc-malachitebft-test -E 'test(future_height_flood)' --no-capture
# Core PoC (already available)
cp <scratch>/poc_future_height_buffer.rs crates/core-consensus/tests/ && \
cargo test -p arc-malachitebft-core-consensus --test poc_future_height_buffer -- --nocapture
```

Safety: everything binds to `127.0.0.1`; scale `EXT_LEN` and message counts to the runner's memory;
never point the injector at a non-test network.

## 7. Exit criteria

- H1–H6 each have at least one green test in Tier A/B on the unfixed tree.
- Tier C report (if run) records RSS growth per flooded height and whether OOM occurred.
- After the fix, every §5 regression test is green and T3/T4 on the fixed tree show `queue_size` bounded by bytes and the `H+1` proposal retained.
