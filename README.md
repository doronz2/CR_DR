# CR-DR — Coercion-Resistant Voting with Private Dispute Resolution

Rust + Circom/Groth16 **research reference implementation** of the
construction from the paper *"Coercion-Resistant Voting with Private Dispute
Resolution"*.

> **THIS IS A RESEARCH PROTOTYPE, NOT PRODUCTION CRYPTOGRAPHY.**
> It implements the **construction and its correctness checks** only. It
> deliberately does **not** implement the coercion-resistance real/ideal
> experiment, hybrid proof games, adversary game logic, or cast-as-intended
> verification.

---

## 1. The problem

The protocol combines two properties that are normally in tension:

* **Coercion resistance** — a voter who is told *"give me your voting secret
  and vote for X"* must be able to **fake compliance**: hand over
  convincing-looking data, and still cast her real vote later.
* **Dispute resolution** — a voter who claims her ballot was not recorded or
  not tallied must be able to get a judge to decide whether she or the
  election authority is at fault.

The tension: dispute-resolution evidence tends to become a **receipt**. If
the voter holds everything needed to prove her ballot was valid and how it
voted, she can also show that evidence to a coercer or vote buyer. CR-DR
resolves this with **private dispute resolution**: part of the evidence is
available to the authority and the judge, but *never* to the voter or the
public.

## 2. The core idea — split validity

Validity of a ballot depends on **two nonces**:

| value    | who knows it |
|----------|--------------------------------------------------|
| `R_i`    | **only** the voter (sampled voter-side; never an authority input) |
| `R_EA,i` | **nobody in the plain** — threshold-shared t-of-k among the authority servers at generation time; only a ≥ t quorum (the *logical* EA) can reconstruct |

Preprocessing is a threshold-private functionality: the voter samples and
keeps `(sk_i, vk_i, R_i)`; the authority side threshold-generates `R_EA,i`
(Shamir t-of-k, plain value erased — any < t coalition holds shares that
are independent of it, and no authority ever sees `R_i`). Only inside the
functionality do the two nonces meet, exactly long enough to publish a
binding-but-hiding commitment into the **indexed** registration table
(voter id = Merkle leaf index):

```text
Reg[i] = (i, vk_i, h_i)
h_i    = H_com(eid, i, vk_i, R_i, R_EA,i)      (Poseidon)
leaf_i = H_reg(eid, i, vk_i, h_i)              (Poseidon)
MR     = Merkle root over (leaf_0, ..., leaf_{N-1})
```

A ballot is cast in the **CAST-ZK format**: the public board entry is
`B_j = (com_j, ct_open_j, pi_cast_j)` where
`com_j = H_ballot_com(opening_j, r_com_j)` commits to the opening
`(eid, i, vk_i, m, R, sigma)` with `sigma = Sign_sk_i(eid, i, m, R)`,
`ct_open_j = Enc_pkEA(opening_j, r_com_j; rho_enc_j)` encrypts the same
data to the EA (BabyJubJub-ElGamal + Poseidon-pad hybrid), and `pi_cast_j`
is a small ZK proof (6,095 constraints, ~50 ms to produce) that `com` and
`ct_open` open to the SAME data. `pi_cast` is **verified publicly before
tallying** — never inside the tally circuit — so the EA can always decrypt
exactly the committed opening, and the tally circuit HARD-checks that the
decrypted opening opens `com` (the prover cannot withhold an opening to
soft-invalidate a ballot). The protocol supports **two admission paths**, never
mixed implicitly:

* **Path 1 — public anonymous cast-ZK**: voters post raw entries
  `B = (com, ct_open, pi_cast)` anonymously onto **BB_raw** (exact bytes
  preserved); ANYONE recomputes the admitted board
  `BB_adm = Clean(BB_raw)` by verifying every pi_cast
  (`protocol::admission::clean`). Fake-compliance and chaff entries pass
  admission (their pi_cast is valid!) and fail only the hidden validity
  inside the private tally relation. The EA obtains tally openings by
  decrypting the admitted ct_opens.
* **Path 2 — EA-mediated private submission**: the voter privately sends
  `(com, opening, r_com)` to the EA; the EA checks ONLY that the opening
  opens com and returns `receipt = Sign_EA(eid, com, timestamp)` — the
  receipt certifies ADMISSION only, never hidden validity or counted
  status, so fake-nonce ballots receive identical receipts (no coercion
  test). The EA later posts BB_adm; recorded-as-cast disputes use the
  receipt.

The exact tally proof is COMMON to both paths: it runs over
`BB_adm = [com_1..com_M]`, hard-opens every commitment with the witness
opening, and computes private validity + sorted-record duplicates.

* **Uncoerced voter:** signs with her real `R_i`; the authority — who knows
  `R_EA,i` — recomputes `h_i` and checks the Merkle relation. Valid.
* **Coerced voter:** surrenders her **real signing key** `sk_i` and a
  **fake nonce** `R*`, and signs whatever the coercer demands. Everything
  the coercer can check, checks out: the key is real, the signature is
  valid, the ballot is well-formed. But the fake ballot fails the hidden
  relation `h_i = H_com(eid, i, vk_i, R*, R_EA,i)` — and the coercer
  **cannot run this test**, because it requires `R_EA,i`. The voter later
  casts her real ballot anonymously.

That is the central trick. Everything else protects it:

* **Validity before duplicates (critical invariant).** FilterAndTally
  establishes validity *first*, and only then applies the duplicate rule
  (**first-valid-ballot-counts**). An invalid fake ballot never consumes
  the voter's slot — a fake posted *before* the real ballot cannot block it.
* **Chaff.** Anyone may post chaff: well-formed ballots for unregistered
  identities that FilterAndTally rejects. Fake-compliance ballots hide in
  this background of invalid traffic (same public shape, same rejection
  class, no markers).
* **Exact ZK tally.** The authority proves in zero knowledge that the
  public tally is the *exact* result of FilterAndTally over the *whole*
  board — without revealing which ballots were valid, who was counted, why
  a ballot was rejected, or any nonce. "Exact" matters: a proof of "some
  valid subset sums to T" would let the authority silently drop valid
  ballots.
* **Private judge.** Disputes are resolved by a judge who may privately
  see `R_EA,i` (directly or reconstructed from threshold shares). The
  voter and the public never see it, so the dispute machinery yields no
  transferable receipt. Detailed verdicts stay judge-private — they can
  leak whether a voter used a real or fake nonce.

## 3. What the implementation demonstrates

Each item is enforced by tests (see `tests/`):

1. A real ballot is counted. (`voting_tests`)
2. A fake-compliance ballot is rejected — at the hidden-nonce check, while
   its signature verifies for the coercer. (`fake_compliance_tests`)
3. A fake ballot **before** the real ballot does not block it.
   (`fake_compliance_tests`, `negative_attack_tests`)
4. Only the first valid ballot per voter counts. (`duplicate_rule_tests`)
5. Public outputs reveal no accepted identities and no rejection reasons.
   (`zk_statement_tests`, `negative_attack_tests`)
6. The Groth16 proof verifies the exact tally relation.
   (`groth16_integration_tests`)
7. A wrong tally fails both the native relation check and proving.
   (`zk_statement_tests`, `groth16_integration_tests`)
8. State separation is structural: `VoterState` cannot carry `R_EA,i`;
   the authority state holds only threshold shares of `R_EA,i` and cannot
   recover `R_i`; fewer than `t` shares reconstruct nothing.
   (`preprocessing_tests`)
9. The judge resolves validity disputes using `R_EA,i` without giving it to
   the voter. (`dispute_tests`)
10. Chaff is rejected but indistinguishable from ordinary invalid ballots.
    (`chaff_tests`)
11. The tally prover cannot flip a valid in-range ballot to invalid by
    withholding or substituting its registration path — the indexed row
    fetch is a hard constraint. (`zk_statement_tests`)
12. Strategy A (naive) and Strategy B (sorted-record) duplicate handling
    agree on all boards, randomized included. (`protocol::duplicates`
    tests)

Negative tests additionally demonstrate the attacks when invariants are
broken: duplicates-before-validity lets a coercer cancel votes; publishing
accepted identities leaks forced abstention; leaking `R_EA,i` breaks fake
compliance; public verdicts leak evasion status. (`negative_attack_tests`)

## 4. Quick start

Prerequisites: a recent Rust toolchain (some transitive deps need ≥ 1.85);
for the ZK pipeline also Node.js ≥ 18 and the circom 2 compiler.

```bash
cargo test                          # protocol + relation tests (ZK tests
                                    # skip if circuit artifacts are absent)
cargo run --bin cr_dr -- demo       # end-to-end demo in memory

# ZK pipeline (dev-only trusted setup):
scripts/install_circom_deps.sh      # circom 2 (cargo), snarkjs+circomlib (npm)
scripts/compile_circuits.sh small   # ~116k constraints (Strategy B)
scripts/setup_groth16.sh small      # local ptau + zkey — DEV ONLY
cargo test                          # now includes Groth16 prove/verify
cargo bench --bench prover          # pipeline benchmarks (see §6)
scripts/install_rapidsnark.sh       # optional: native prover (~12-14x faster
                                    # proving; same artifacts + verifier)
```

## 5. Running procedures independently (CLI)

Every protocol procedure is a `cr_dr` subcommand. State is stored as JSON
under an election directory (`--dir`, default `./election`), split by trust
domain: `public/` is world-readable, `authority/` never leaves the EA,
`voters/<id>.json` never leaves voter *i*.

A complete coerced-voter scenario:

```bash
alias cr_dr='cargo run --quiet --bin cr_dr --'

# Election authority
cr_dr setup --eid demo --candidates 0,1,2 --max-voters 8
cr_dr register-voter --id 0
cr_dr register-voter --id 1
cr_dr register-voter --id 2 --cut-and-choose 8   # audited registration
cr_dr finalize-registration                      # publishes MR

# Voter 0 is coerced: fake compliance for the coercer (demands candidate 2)
cr_dr fake-compliance --voter 0 --candidate 2 --out coercer_transcript.json
cr_dr build-fake-ballot --transcript coercer_transcript.json --out fake.json
cr_dr submit --ballot fake.json                  # coercer submits the fake

# Voter 0's real vote, plus other voters and chaff
cr_dr vote --voter 0 --candidate 0 --out real0.json
cr_dr vote --voter 1 --candidate 1 --out b1.json
cr_dr vote --voter 2 --candidate 1 --out b2.json
cr_dr chaff --count 2 --out chaff.json
for b in real0 b1 b2 chaff_0 chaff_1; do cr_dr submit --ballot $b.json; done

# Anonymous channel: shuffle + post (exact bytes preserved)
cr_dr flush-channel
cr_dr show-board

# Tally + proof (authority), verification (anyone)
cr_dr tally            # prints ONLY the public tally: 0->1, 1->2, 2->0
cr_dr prove            # Groth16 proof of the exact FilterAndTally relation
cr_dr verify --proof election/proofs/proof.json --public election/proofs/public.json

# Voter-private recorded-as-cast check (never show this to the coercer!)
cr_dr check-recorded --ballot real0.json

# Private dispute resolution
cr_dr issue-receipt --ballot real0.json --timestamp 1730000000 --out rc.json
cr_dr dispute-recorded --ballot real0.json --receipt rc.json
cr_dr dispute-tally --ballot fake.json           # judge: VoterFaulty (fake nonce,
                                                 # detected privately via R_EA)
# Threshold authority: share R_EA,i, judge reconstructs from t shares
cr_dr share-nonces --t 3 --k 5
cr_dr dispute-tally --ballot fake.json --use-threshold
```

## 6. The ZK circuit

`circuits/main/filter_and_tally.circom` — `FilterAndTally(nB, nC, depth, dupStrategy)`
proves the exact tally over the whole board (Groth16/BN254, Poseidon for all
in-circuit hashes, Schnorr-over-BabyJubJub signature verification in
circuit):

* every posted ciphertext — bound by a Poseidon-chain `bb_commitment` — is
  opened and evaluated;
* per-ballot soft flags (opening ∧ eid ∧ candidate ∧ signature) drive a 0/1
  validity, so invalid ballots make flags false rather than the witness
  unsatisfiable;
* the **indexed registration row** is fetched by the ballot's claimed id:
  the id is decomposed with `Num2Bits_strict` (canonical — no prover
  freedom), `in_range = (id < num_voters)` is a deterministic flag, and for
  active in-range ids the Merkle **direction bits are the bits of id** and
  root equality is a HARD constraint on the witness row `(reg_vk, reg_h)`.
  The prover cannot withhold a valid ballot's path or bind it to another
  row (`zk_statement_tests::prover_cannot_withhold_...`). vk-equality and
  the hidden nonce relation `h = H_com(eid,id,vk,R,R_EA)` stay soft;
  out-of-range / malformed ballots stay soft-invalid;
* each slot emits a private record `r_j = (valid_j, id_j, pos_j, m_j)`;
  duplicates are resolved **after** validity by the sorted-record
  **Strategy B**: a Batcher odd-even mergesort network sorts the records by
  `(-valid, id, pos)` in-circuit (a deterministic network is
  simultaneously a permutation proof and a sortedness proof, with no
  challenge to sample — the sound choice for this Groth16 stack), then
  `counted_j = valid_sorted_j · [j = 0 ∨ id_j ≠ id_{j-1}]` counts the first
  valid ballot per identity in one linear pass. The naive O(B²)
  **Strategy A** is kept as the `*_naive` circuit variants for
  benchmarking;
* the accumulated counts are constrained to equal the public
  `tally_counts`.

Public inputs: `eid_hash, MR, candidate_set_commitment, bb_commitment,
num_ballots, num_voters, duplicate_rule_id, pk_ea_commitment,
tally_counts[]` — and nothing else. `num_voters` is circuit-constrained
(it bounds the in-range window of the indexed table). `pk_ea_commitment`
carries no in-circuit constraints (the witness has no EA key to check it
against); it is bound **natively**: verifiers recompute the whole statement
from public data (`zk::statement::statement_matches_public_data`) and check
the proof's public inputs are exactly that statement
(`zk::circom_io::public_inputs_match`) — the CLI does both on every
`verify` and `dispute-tally`. A native relation checker
(`src/zk/mock_backend.rs`) mirrors the circuit constraint-for-constraint,
including the identical sorting-network schedule; tests keep the two in
agreement. Compile-time variants: small (16 ballots / 3 candidates /
depth 4, ≈116k constraints), medium (128 / 3 / 6, ≈1.0M), each also as a
`*_naive` Strategy-A build — `scripts/compile_circuits.sh
{small|small_naive|medium|medium_naive}`.

### Prover tiers

* **Tier 1 — single prover (implemented, benchmarked below).** One logical
  prover performs authorized ≥ t reconstructions of the `R_EA,i`
  (`AuthoritySecretState::r_ea`), assembles the full witness and runs
  Groth16.
* **Tier 2 — trusted tally environment.** The same algorithm and interface,
  executed inside a protected, audited environment. Nothing in the code
  changes; not separately benchmarked.
* **Tier 3 — decentralized/threshold prover (future).** Threshold
  authorities jointly supply the witness without any single party learning
  everything. The witness builder consumes `R_EA,i` exclusively through the
  share-based `r_ea()` interface, so an MPC opening can replace it without
  changing the relation. Not implemented; **no decentralized proving is
  claimed or benchmarked**.

### Cast-ZK encryption (BabyJubJub-ElGamal + Poseidon-pad hybrid)

Ballot encryption is REAL public-key encryption since the CAST-ZK format:
`ct_open = Enc_pkEA(opening, r_com; rho_enc)` with `C1 = rho_enc*Base8`,
`ss = rho_enc*pk_EA`, `masked_i = m_i + Poseidon(ss.x, ss.y, i)`. The cast
proof `pi_cast` (circuits/main/cast_proof.circom) publicly binds `ct_open`
to `com`; the tally circuit never proves encryption or decryption — it
receives the EA-decrypted opening and hard-checks it against `com`. Two
soft-safety consequences inside the tally relation: the commitment opening
became a HARD gated constraint, and the Schnorr gadget became SOFT-SAFE
for arbitrary field inputs (soft on-curve flags, muxed inputs, complete
Edwards double-and-add for c·A — circomlib's Montgomery ladder is unsafe
for torsion inputs), so no voter-chosen opening can make the tally witness
unsatisfiable. Production encryption still needs a formal treatment
(key-validation ceremonies, CCA transforms).

### ⚠️ Dev-only trusted setup

`scripts/setup_groth16.sh` runs powers-of-tau and phase-2 **locally, with no
ceremony**. Anyone holding the toxic waste can forge tally proofs. Groth16
setup is circuit-specific: recompile ⇒ redo setup. Never use these keys
outside development.

### Benchmarks

`cargo bench --bench prover` (criterion, `benches/prover.rs`) runs the full
SINGLE-PROVER (Tier 1) pipeline. Groups: `e2e_small` / `e2e_medium` (every
native stage), `duplicates` (Strategy A vs B natively at 16/128/1024),
`groth16_small` / `groth16_medium` (circuit witness generation, prove,
verify — for BOTH circuit strategies; a group skips if its artifacts are
absent). Each group prints its instance parameters at startup. See
BENCHMARKS.md for the full measured report (machine, toolchain, commands,
all tables); headline Apple-M3-Max numbers:

| stage | small (16 slots, 116k constraints) | medium (128 slots, 1.01M constraints) |
|---|---|---|
| native FilterAndTally | 14 ms | 106 ms |
| witness construction | 20 ms | 159 ms |
| native relation check | 14 ms | 122 ms |
| circuit witness generation (wasm) | 0.64 s | 4.1 s |
| Groth16 prove — snarkjs (incl. witness gen) | 4.2 s | 31 s |
| Groth16 prove — **rapidsnark** (native, prove step) | **0.25 s** | **2.2 s** |
| Groth16 verify | 0.21 s | 0.21 s |
| prove peak RSS (snarkjs / rapidsnark) | 2.7 GB / 0.15 GB | 7.6 GB / 1.1 GB |

Native duplicate handling (Strategy A naive vs Strategy B sorted): A wins at
16 records (52 ns vs 104 ns), B wins from 128 (1.15 µs vs 2.11 µs) and is
12.5× faster at 1024 (12.6 µs vs 157 µs); in-circuit the two are within
0.1% constraints at 128 slots with the crossover at ≈128.

Groth16 proving cost is set by the compiled circuit size (roughly linear in
constraints — small ≈ 116k, medium ≈ 1.0M), not by how many board slots are
occupied; one proof covers the whole board, so the cost is per-tally, not
per-ballot. Verification is constant-time in circuit size (~0.2 s is
node/snarkjs startup, not the pairing check). These are Tier-1 numbers: one
logical prover with the full witness. No decentralized proving is
benchmarked.

### Scaling beyond one circuit: the chunked pipeline

The monolithic circuit is practical to ~10^3 voters on a laptop and capped
near ~10^4 by memory and the largest public powers-of-tau (2^28). The
CHUNKED pipeline (design: **CHUNKED_TALLY_DESIGN.md**; implemented) proves
the same relation as K fixed-size chunk proofs plus public aggregation
checks: K `ValidityChunk` proofs (the monolithic per-slot stage verbatim +
board-chain segment + blinded record commitment), K `SortedRunChunk`
proofs (sortedness across hiding boundary commitments, first-valid
counting, committed partial tallies, grand products under a Fiat-Shamir
challenge derived AFTER both record AND sorted-run commitments), and one
`TallySum` proof opening only the total. 24-bit board positions support up
to 2^24 slots with the same fixed circuits (one ceremony each, independent
of N).

Run it end-to-end on one machine with the parallel driver:

```bash
cargo run --release --bin prove_chunked -- --ballots 20480   # N=10^4 row
```

which proves all 2K+1 chunk proofs with `cores/6` concurrent rapidsnark
jobs and verifies the aggregate. Measured laptop numbers and the composed
cost projection are in **BENCHMARKS.md**; **GCP_RUNBOOK.md** has a
one-command cloud recipe (c3d-highcpu-90 spot) for the measured N = 10^4
run.

## 7. Threshold authority

A single authority knowing all `R_EA,i` is a trust point — it can
distinguish real from fake nonces. The intended model is therefore a single
LOGICAL EA implemented by `k` threshold authorities: every `R_EA,i` is
Shamir-shared t-of-k **at generation time** (inside the preprocessing
functionality — the plain nonce is erased immediately) and every use of a
nonce afterwards (tally witness, judge dispute) is an *authorized ≥ t
reconstruction* (`AuthoritySecretState::r_ea`). Two models are implemented:

* **Trusted-dealer Shamir** (`threshold/trusted_dealer.rs`): each `R_EA,i`
  is split into `k` shares, threshold `t`. Any `t` reconstruct; any `t−1`
  shares are information-theoretically independent of the secret.
  `share_all_nonces` re-shares under new parameters via an authorized
  quorum (share rotation / t,k change).
* **Malicious preprocessing view model**
  (`threshold/malicious_view_model.rs`): the `ThresholdViewSimulator` trait
  fixes the simulation target precisely — the **honest-generated portion of
  the corrupted authorities' view** (honest messages, honest commitments,
  honest public transcript, shares delivered by honest parties). The
  adversary's own corrupted-party inputs/messages are **auxiliary input**,
  passed as context and never simulated. The simulator never receives any
  `R_EA,i`; in the trusted-dealer special case it can sample the < t
  corrupted shares uniformly, precisely because they are independent of the
  secret.

Cut-and-choose registration (`register-voter --cut-and-choose q`) models the
audit intuition: `q` candidate pairs, `q−1` audited by opening `R_EA^k`, the
unopened pair becomes the voting pair; a dealer corrupting one pair survives
with probability ≈ `1/q` (tested empirically). **This is not a full
malicious VSS/DKG.**

## 8. Private dispute resolution

* **Recorded-as-cast (Path 1, public cast-ZK).** A raw submission is
  `(com, ct_open, pi_cast)`, and byte presence alone is NOT admission:
  `Clean(BB_raw)` keeps an entry only if a verifying `pi_cast` accompanies
  it. The voter's check (`check-recorded`) and the adjudication
  (`dispute-recorded` without a receipt) are therefore PROOF-AWARE: they
  look for the exact entry bytes on `BB_raw` **and** a verifying `pi_cast`
  at a matching index. Entry present + verifying proof ⇒ admitted,
  complaint unfounded (`VoterFaulty` internally). Entry present but proof
  missing/invalid ⇒ `Undetermined` — Clean drops the entry, and the
  channel model carries no acknowledgments, so a stripped proof is not
  attributable. Entirely absent ⇒ `Undetermined` for the same reason.
  Checking is optional for coercion resistance — if a coercer demands to
  see a ballot, the voter shows the *fake* one.
* **Recorded-as-cast (Path 2, EA-mediated).** The EA's admission receipt
  `Sign_EA(eid, com, timestamp)` certifies ADMISSION ONLY (fake-nonce
  ballots get identical receipts). A valid receipt whose commitment is
  absent from the posted `BB_adm` ⇒ `AuthorityFaulty` (the EA posts the
  board in this model; with a distinct board operator it would be
  `BoardFaulty`).
* **Tallied-as-recorded.** The judge privately receives the complainant's
  ballot opening and `R_EA,i` — either from the EA or reconstructed from
  ≥ t threshold shares — plus the EA-private openings store for the
  admitted board. It re-runs the validity checks itself and RECOMPUTES the
  duplicate rule from the openings (never trusting authority-computed
  validity labels): commitment binding forces each supplied opening to be
  THE opening of its admitted commitment, so a fabricated prior opening ⇒
  `AuthorityFaulty`. **Evidence-incompleteness policy:** if the authority
  supplies fewer prior openings than the board requires, the verdict is
  `Undetermined`, not `AuthorityFaulty` — non-cooperation is not
  cryptographically attributable in this model; a deployment may layer an
  administrative rule (failure to produce evidence when summoned counts as
  fault) on top. The judge also checks the public tally proof against the
  current statement (`TallyProofStatus`): an invalid proof ⇒
  `AuthorityFaulty`; a missing/uncheckable proof is `Unavailable` and the
  complaint stays `Undetermined` — the judge never assumes a proof
  verifies; a valid first ballot with a verifying proof ⇒
  `NoAuthorityFault`.
  Verdicts: `AuthorityFaulty` / `VoterFaulty` / `BoardFaulty` /
  `NoAuthorityFault` / `Undetermined`; externally released verdicts are
  coarsened (`JudgeReport::external_verdict`): `VoterFaulty` ⇒
  `NoAuthorityFault`, so a dispute outcome can never serve as a coercer's
  nonce test. A fake nonce is detected here **privately** — the voter
  never learns `R_EA,i`, so nothing transferable is created.

Leakage discipline: the voter and the public never receive `R_EA,i`;
detailed verdicts may reveal real-vs-fake nonce usage and are therefore
**not** part of the coercion-resistance adversary view unless explicitly
modeled as leakage (demonstrated in `negative_attack_tests`).

**Cast-as-intended is out of scope** by design: evidence that a ballot
encodes a particular candidate is exactly the artifact that becomes a
receipt in a coercer's hands; it needs a separate treatment.

## 9. Code map — what is implemented where

### Crate root

| file | implements |
|---|---|
| `src/lib.rs` | Crate root: module tree and re-exports; scope statement (construction only, no CR game). |
| `src/main.rs` | The **`cr_dr` CLI**. One subcommand per protocol procedure (`setup`, `register-voter`, `finalize-registration`, `vote`, `fake-compliance`, `build-fake-ballot`, `chaff`, `submit`, `flush-channel`, `show-board`, `tally`, `prove`, `verify`, `check-recorded`, `issue-receipt`, `dispute-recorded`, `dispute-tally`, `share-nonces`, `demo`). Defines the election-directory layout and enforces the trust split (`public/` vs `authority/` vs `voters/<id>.json`): `public/board.json` holds ciphertexts only, the EA payloads (openings) go to `authority/ballot_payloads.json`, and `verify`/`dispute-tally` bind the proof's public inputs to the statement recomputed from public data. |
| `src/bin/gen_example_inputs.rs` | Deterministically regenerates the checked-in circuit inputs in `circuits/input_examples/` (a valid mixed board, and the fake-before-real scenario), asserting they satisfy the native relation. |
| `src/bin/prove_chunked.rs` | Parallel single-machine driver for the chunked pipeline: builds a synthetic election at a target board size, proves all 2K+1 chunk proofs with `cores/6` concurrent rapidsnark jobs, verifies the aggregate (proofs + public-input bindings). |
| `src/types.rs` | All core protocol types: `F` (BN254 scalar), `PublicParams`, `ElectionConfig`, `DuplicateRule` (+ its statement id), `ThresholdParams`, `VoterState` (sk_i, vk_i, R_i — **cannot** carry R_EA,i), `PublicRegistrationRecord` (h_i, leaf_i), `AuthorityVoterSecret` / `AuthoritySecretState` (where R_EA,i lives), `BallotPlaintext` with the canonical **9-field encoding** `[eid_hash, id, vk.x, vk.y, candidate, R, sig.Rx, sig.Ry, sig.S]` (`to_fields`/`from_fields`), `Ballot` (ciphertext + EA-only payload; `.public()` projects the board-safe part, `.bytes()` derives the exact public encoding — never stored), `PublicBallot` (ciphertext only — the ONLY per-ballot data on the public board), `AuthorityBallotPayloads` (EA-private payload store aligned with board order), `TallyResult` (the only public tally output), `InternalBallotStatus`/`InternalBallotEvaluation` (test/debug only, deliberately non-serializable). Also the field⇄decimal-string serde helpers (`f_to_dec`, `f_from_dec`, `fserde`). |
| `src/errors.rs` | `CrDrError` (thiserror): config, duplicate-voter, crypto, Merkle, threshold, cut-and-choose audit, ZK-toolchain errors. |

### `src/crypto/` — primitives (layer A: native, circuit-compatible)

| file | implements |
|---|---|
| `poseidon_native.rs` | `poseidon(&[F]) -> F` via `light-poseidon`, parameter-identical to circomlib's `Poseidon`; unit tests pin known circomlibjs vectors. Every in-circuit hash routes through this. |
| `hash.rs` | All protocol hashes: `eid_to_field` (SHA-256 → field, outside the circuit), **`h_com`** (`H_com`, arity 6), **`h_reg`** (`H_reg`, arity 5), `sig_msg_hash` (arity 4), `ct_commit` (H_ballot_com, the ballot commitment, arity 10), `merkle_hash` (arity 2), `bb_commitment` (Poseidon chain over posted ciphertext fields), `candidate_set_commitment`, `pk_ea_commitment`, `ballot_hash` (for receipts). |
| `signature.rs` | The ZK-friendly signature: **Schnorr over BabyJubJub with Poseidon challenge** — `keygen`, `sign`, `verify` (checks `S·B8 == R + c·A`), `challenge`. Also the circomlib⇄arkworks curve-form isomorphism (`to_circom_point`/`from_circom_point`, `x_ark = √168700·x_circom`), circomlib `Base8` constants, scalar embedding helpers (`jub_scalar_from_field`, `f_is_canonical_scalar`), point decoding with subgroup checks, and scalar serde. |
| `encryption.rs` | CAST-ZK encryption: `CastCiphertext` (C1 + masked[10]), `cast_encrypt`/`cast_decrypt` (BabyJubJub-ElGamal + Poseidon-pad hybrid, deterministic given rho_enc — matches cast_proof.circom), `CastSecret` (opening, r_com, rho_enc — voter-held), `sample_rho_enc`, EA keygen. |
| `merkle.rs` | Fixed-depth Poseidon Merkle tree over registration leaves: `MerkleTree::new/root/path`, `MerklePath`, `verify_path` — bit-for-bit the circuit's `MerkleMembership`. |
| `shamir.rs` | Shamir secret sharing over BN254: `share` (degree t−1 polynomial), `reconstruct` (Lagrange at 0), with tests that <t shares don't reconstruct. |

### `src/protocol/` — the construction

| file | implements |
|---|---|
| `setup.rs` | `setup_election(config)` → (`PublicParams`, `AuthoritySecretState`): validates candidates/capacities/threshold params; generates the EA encryption keypair and EA receipt-signing keypair. |
| `preprocessing.rs` | **Threshold-private registration** (idealized functionality F_prep). `voter_registration_secrets`: the VOTER samples (sk_i, vk_i, R_i). `preprocess_voter`: authority side threshold-generates R_EA,i (Shamir t-of-k, plain value erased), F_prep computes h_i/leaf_i; voter gets (sk,vk,R), authority gets ONLY shares, public gets (i, vk_i, h_i, leaf_i). `finalize_registration`: enforces DENSE ids 0..N-1 (indexed table: id = leaf index), Merkle tree over leaves, `RegistrationState`. **Cut-and-choose**: `preprocess_voter_cut_and_choose` (voter's R fixed; q candidate R_EA^k, q−1 audited by opening, unopened pair final + threshold-shared), `..._with_cheat` (test hook), `estimate_cut_and_choose_soundness` (Monte-Carlo ≈ 1/q). |
| `vote.rs` | `seal_ballot` — the CAST-ZK sealing shared by real votes, fake-compliance and chaff (com + ct_open + CastSecret); `cast_vote`: candidate check, `sigma = Sign_sk(eid, i, m, R_i)`, seal. |
| `fake_compliance.rs` | **The coercion story.** `FakeComplianceTranscript` — what the voter surrenders (REAL sk_i, FAKE nonce R*, requested candidate, valid signature). `fake_compliance` builds it (samples R* ≠ R_i); `build_fake_ballot` produces the coercer's ballot, publicly indistinguishable from a real one. |
| `admission.rs` | The two admission paths. Path 1: `clean` (BB_adm = Clean(BB_raw), keep valid-pi_cast entries), `ea_open_admitted` (EA decrypts admitted ct_opens). Path 2: `ea_admit_private` (admission-level check ONLY + Sign_EA(eid, com, ts) receipt), `EaAdmissionState`. `AdmittedOpenings` (EA-private, aligned with BB_adm); `admitted_from_ballots` (test/bench helper modeling an already-admitted board). |
| `chaff.rs` | `chaff_ballot`: fresh unregistered identity, in-range voter id, valid signature — passes every syntactic check, fails only the hidden registration relation; same shape and rejection class as fake ballots. |
| `bulletin_board.rs` | `BulletinBoard` (**BB_raw**: raw (com, ct_open) entries, exact-bytes membership for Path-1 recorded-as-cast), `AdmittedBoard` (**BB_adm**: the admitted commitment list the tally processes), `RawSubmission` (entry + pi_cast), `AnonymousChannel` (drops sender identity, shuffles, preserves bytes). |
| `filter_and_tally.rs` | **Exact FilterAndTally.** Per ballot: (a) open/decrypt → (b) parse → (c) eid → (d) candidate ∈ C → (e) signature → (f)-(h) `registration_check` — the shared deterministic INDEXED-row predicate (row Reg[id] selected by the claimed id; vk equality; hidden nonce relation via authorized ≥t R_EA reconstruction; leaf/root consistency) → (i) *only now valid* → emit record r_j. Duplicates via sorted-record Strategy B (`duplicates.rs`), then tally. `registration_check` is also the judge's predicate — tally and disputes always agree. Validity-before-duplicates lives here. |
| `duplicates.rs` | Duplicate strategies over private records r_j = (valid, id, pos, m): `counted_flags_naive` (Strategy A, O(B²) reference) and `counted_flags_sorted` (Strategy B, MAIN: sort by (-valid,id,pos), explicit multiset-equality check, linear first-in-identity-block pass). Both agree on all inputs (tested incl. randomized). |

### `src/threshold/` — authority-nonce threshold models

| file | implements |
|---|---|
| `trusted_dealer.rs` | Model 1: `share_nonce` / `reconstruct_nonce` (Shamir on each R_EA,i), `share_all_nonces` (authorized ≥t RE-share under new t,k — shares exist from registration time), `authority_share` (a single authority's share). |
| `malicious_view_model.rs` | Model 2: the `ThresholdViewSimulator` trait — simulates **only the honest-generated part** of corrupted authorities' views; `AdversaryAuxiliaryState` carries the adversary's own inputs/messages as *context, never output*; `SimulatedCorruptedAuthorityView`; `TrustedDealerShamirSimulator` (samples <t shares uniformly — valid precisely because <t Shamir shares are secret-independent; constructed from public data only, no R_EA,i anywhere in its API). |

### `src/zk/` — the exact-tally proof

| file | implements |
|---|---|
| `mod.rs` | `CircuitShape` (compile-time NB/NC/depth) and `SMALL_SHAPE` = (16, 3, 4), matching the compiled small circuit. |
| `statement.rs` | `TallyStatement` — the public inputs and nothing else (eid_hash, MR, candidate-set commitment, bb_commitment, counts, sizes, rule id, pk_ea commitment); `build_tally_statement` from public data only; `statement_matches_public_data` — the native check verifiers must run alongside the proof (binds `num_voters`/`pk_ea_commitment`, which the circuit cannot constrain). |
| `witness.rs` | `TallyWitness`/`BallotWitnessRow` (per-ballot private inputs: ct, 9 plaintext fields, rho, R_EA, indexed row values reg_vk/reg_h, sibling path at index id — direction bits are id's own bits, not witness). Documents the **prover tiers** (Tier 1 single prover implemented; Tier 3 replaces the share-based `r_ea()` call with MPC). `build_tally_witness` mirrors FilterAndTally and applies the **dummy-substitution policy** for hard-constraint-unsafe ballots. `padding_row`/`padded_rows` fill circuit slots beyond `num_ballots`. |
| `mock_backend.rs` | `relation_check_native` — the native mirror of the circuit, constraint-for-constraint: soft flags, deterministic strict-bits in-range flag, HARD gated indexed-row/root check (unsatisfiable ⇒ false), `batcher_schedule` (THE sorting-network schedule, shared with the circom side), sorted-record counting, BB chain, tally equality. Includes `circuit_sig_ok` with **bit-exact integer scalar multiplication** (`mul_bits`) matching circomlib semantics. |
| `cast.rs` | pi_cast: `prove_cast` / `verify_cast_entry` (public-input binding + Groth16 verify + C1 subgroup check), `cast_relation_check_native` (mirror), input serialization. Verified PUBLICLY before tallying; never inside the tally circuit. |
| `chunked.rs` | The CHUNKED pipeline: `build_chunked_tally` (records via the shared `eval_row`, global sort, blinded rc/sc commitments, Fiat-Shamir challenges, boundary chain, partial tallies, grand products), `chunked_relation_check_native` (every chunk-circuit constraint + every aggregator check), circom input serialization and expected public-input vectors per proof. |
| `circom_io.rs` | `generate_witness_input` — serializes (statement, witness) into the circuit's `input.json` (decimal strings, signal names matching the main component); `statement_public_inputs`/`public_inputs_match` — the exact snarkjs `public.json` a proof of a statement must carry (verifiers reject proofs bound to any other statement). |
| `groth16_backend.rs` | `SnarkjsBackend` — Groth16 via the snarkjs CLI: artifact discovery (`toolchain_available`), `generate_witness` (wasm), `prove` → (proof.json, public.json), `verify`. Race-free per-call work directories. `RapidsnarkBackend` — optional NATIVE prover (iden3 rapidsnark, C++): same .zkey/.wtns, ~12–14× faster prove step, proofs verify under the same snarkjs verification keys (`discover` via $RAPIDSNARK_PROVER or the build tree). |

### `src/disputes/` — private dispute resolution

| file | implements |
|---|---|
| `judge.rs` | `Verdict` (`AuthorityFaulty`/`VoterFaulty`/`BoardFaulty`/`Undetermined`) and `JudgeReport` — judge-private, never contains R_EA,i. |
| `recorded_as_cast.rs` | Direct mode: `check_direct` (exact byte membership). Authority-mediated mode: `SubmissionReceipt` = `Sign_EA(eid, ballot_hash, timestamp)`, `ea_issue_receipt`, `verify_receipt`, and `adjudicate_recorded_as_cast` (valid receipt + missing bytes ⇒ `BoardFaulty`). |
| `tallied_as_recorded.rs` | `judge_tallied_as_recorded` — the paper's checks 1–7: ballot opens to the claimed plaintext; signature verifies; `h = H_com(…, R, R_EA,i)` against the public record (**this is where a fake nonce is privately detected**); leaf/MR consistency (mismatch after a good h ⇒ `AuthorityFaulty`); duplicate status under the public rule; tally-proof status (`TallyProofStatus`: `Verified`/`Invalid`/`Unavailable` — a missing proof is never assumed valid). `NonceSource` lets the judge take R_EA,i directly from the EA or reconstruct it from ≥t threshold shares. |

### `circuits/` — the Circom side

| file | implements |
|---|---|
| `components/poseidon_hashes.circom` | `HCom`, `HReg`, `MessageHashForSignature` — the three protocol hashes as Poseidon gadgets (arities 6/5/4, matching `crypto/hash.rs`). |
| `components/merkle_membership.circom` | `MerkleMembership(depth)` — generic soft membership check (kept for reference; ballot validity now uses the HARD id-indexed row fetch inside `ballot_validity.circom`). |
| `components/signature_verify.circom` | `SchnorrVerify` — SOFT-SAFE in-circuit Schnorr: soft Edwards on-curve flags with Base8 muxing, COMPLETE double-and-add for c·A (`CompleteEscalarMul`; safe for identity/torsion), strict S decomposition with soft top-zero flag, `EscalarMulFix` for S·Base8. Never unsatisfiable for any field inputs. |
| `main/cast_proof.circom` | `CastProof` — pi_cast: com = Poseidon(opening ‖ r_com) AND ct_open = hybrid-Enc(pk_EA, opening ‖ r_com; rho_enc), rho_enc ≠ 0. All-hard (a failing pi_cast rejects the entry publicly, pre-tally). 6,095 constraints. |
| `components/ballot_validity.circom` | `BallotValidity(depth, nCand)` — soft flags (opening ∧ eid ∧ candidate one-hot ∧ signature ∧ vk-match ∧ nonce-relation) × deterministic `in_range` (strict id bits) × active; HARD gated indexed-row fetch: leaf = HReg(eid, id, reg_vk, reg_h), Merkle directions = bits of id, root === MR. Emits the record fields (`valid`, `id_eff`, `m`, `candSel`). |
| `components/duplicate_first_valid.circom` | `DuplicateFirstValid(nB)` — Strategy A (benchmark baseline), O(B²): `counted[j] = valid[j] · Π_{k<j}(1 − valid[k]·same_id(k,j))`; invalid ballots can never block. |
| `components/sort_records.circom` | Strategy B permutation machinery: `CompareExchangeRecord` (packed key `(1-valid)·2^16 + id·2^8 + pos`, GreaterThan(17) + conditional swap) and `SortRecords(nB)` — Batcher odd-even mergesort network (schedule identical to `mock_backend::batcher_schedule`); sorted-by-construction = sound permutation + sortedness with no sampled challenge. |
| `components/duplicate_sorted.circom` | `DuplicateTallySorted(nB, nC)` — Strategy B (MAIN): sort records, `counted_j = valid_sorted_j·(1 − same_id_prev)`, then `tally_counts[c] === Σ counted_j·[m_j = c]`. Sorted order stays private. |
| `components/tally_accumulator.circom` | `TallyAccumulator(nB, nC)` — sums `counted·candSel` per candidate and constrains equality with the public `tally_counts`. |
| `main/filter_and_tally.circom` | `FilterAndTally(nB, nC, depth, dupStrategy)` — the whole relation: duplicate-rule pin, candidate-set commitment opening, `num_ballots` range + active flags, per-ballot validity, the BB Poseidon-chain binding, duplicates, tally. |
| `main/filter_and_tally_{small,medium}.circom` (+ `_naive`) | Instantiations of `FilterAndTally(nB, nC, depth, dupStrategy)`: small = (16,3,4) — 144,339 constraints (B) / 143,300 (A-naive); medium = (128,3,6) — 1,235,915 (B) / 1,234,980 (A). Public-input list declared here. |
| `input_examples/*.json` | Ready-to-prove inputs: `small_valid_input.json` (real + fake + chaff) and `fake_before_real_input.json` (the critical invariant, provable). |

### `scripts/` — ZK toolchain

| file | does |
|---|---|
| `install_circom_deps.sh` | Installs circom 2 (cargo) and snarkjs + circomlib (npm, repo-local). |
| `install_rapidsnark.sh` | Builds the optional rapidsnark NATIVE prover into `build/rapidsnark-src` (macOS links Homebrew GMP). Drop-in for the prove step only; snarkjs stays the witness generator and verifier. |
| `compile_circuits.sh [small\|medium]` | `circom → r1cs + wasm + sym` into `build/circuits`, prints constraint counts. |
| `setup_groth16.sh [variant]` | **Dev-only** setup: sizes the power of tau from the constraint count, generates a local ptau (new/contribute/prepare), Groth16 phase-2, exports the verification key. |
| `prove.sh <input.json> [variant]` | Witness (wasm) + `snarkjs groth16 prove`. |
| `verify.sh [proof] [public] [variant]` | `snarkjs groth16 verify`. |

### `tests/` — 12 suites

| file | covers |
|---|---|
| `setup_tests.rs` | Config validation; parameter consistency. |
| `preprocessing_tests.rs` | State separation: `VoterState` cannot carry R_EA,i (exhaustive field list); authority state cannot recover R_i (no field, value absent from serialization); < t shares reconstruct nothing, ≥ t do; h/leaf correctness via authorized reconstruction; DENSE-id enforcement for the indexed table; duplicate-id rejection; cut-and-choose honest/cheating runs and the ≈1/q soundness estimate. |
| `voting_tests.rs` | Real ballots count; candidate/registration guards; exact-byte ballot encoding. |
| `fake_compliance_tests.rs` | Coercer-side signature verifies; fake rejected at the nonce relation; **fake-before-real doesn't block**; shape indistinguishability. |
| `chaff_tests.rs` | Chaff rejected; same shape and rejection class as fakes; no markers. |
| `filter_and_tally_tests.rs` | Every rejection path (decryption/format/eid/candidate/signature/wrong-key/nonce), duplicates, empty board. |
| `duplicate_rule_tests.rs` | First-valid-counts; invalid ballots never consume slots; cross-voter independence. |
| `zk_statement_tests.rs` | Native relation accepts valid witnesses, rejects wrong tallies and every tampered public input; witness flags match the tally; the statement leaks no identities/labels; the prover cannot withhold/substitute an in-range ballot's registration path (hard indexed row ⇒ UNSAT); num_voters is relation-constrained. |
| `groth16_integration_tests.rs` | Real prove+verify; tampered public input rejected; wrong tally unprovable; cross-instance mismatch rejected; proof/public contain no witness data. Skips cleanly if artifacts are absent. |
| `dispute_tests.rs` | Recorded-as-cast present/absent/receipt; private fake-nonce detection; judge never leaks R_EA; threshold-share reconstruction path; duplicate complaints. |
| `threshold_tests.rs` | Shamir t-of-k reconstruction; <t failure; simulator API takes no secrets; aux is context, not output; refuses ≥t corruptions. |
| `negative_attack_tests.rs` | The broken-variant demonstrations: duplicates-before-validity enables vote cancellation; published identities leak forced abstention; leaked R_EA breaks fake compliance; public verdicts leak evasion. |

### `benches/`

| file | covers |
|---|---|
| `prover.rs` | Criterion benchmarks for the proving pipeline (see §6 “Benchmarks”): native stages (`filter_and_tally`, statement/witness building, native relation check, input serialization) and the real snarkjs stages (wasm witness generation, Groth16 prove, verify). The groth16 group skips cleanly if artifacts are absent. |

## 10. Design notes & compatibility

* All circuit-facing values are BN254 scalar field elements; field elements
  serialize as decimal strings (circom's input format).
* Native Poseidon is `light-poseidon` (circomlib-parameter-compatible,
  pinned by test vectors against circomlibjs).
* BabyJubJub points are stored in **circomlib coordinates**
  (`168700·x² + y² = 1 + 168696·x²y²`); arithmetic maps internally to
  arkworks' isomorphic `a = 1` form (`x_ark = √168700 · x_circom`).
* The signature is Schnorr over BabyJubJub with a Poseidon challenge,
  verified in-circuit by a SOFT-SAFE gadget: soft on-curve flags, off-curve
  inputs muxed to `Base8`, a complete Edwards double-and-add for `c·A`
  (circomlib's Montgomery-ladder `escalarmulany` is unsatisfiable on
  torsion inputs), `escalarmulfix` for `S·Base8`, and a soft S-canonicity
  flag (`S < l`) matching the native verifier's rule — the native verifier
  and the circuit agree on every input (see `tests/soft_safety_tests.rs`).
* Poseidon arities double as (weak) domain separation between `H_com` (6),
  `H_reg` (5), the signature message hash (4) and the ciphertext
  commitment (10); production needs explicit domain tags.
* Per-ballot internal statuses (`InternalBallotEvaluation`) are
  test/debug-only, deliberately non-serializable, and never published.

## 11. Known limitations (summary)

1. Dev-only Groth16 setup; no ceremony (Hermez ptau + local phase-2).
2. Cut-and-choose models the audit intuition, not a malicious VSS/DKG.
3. The anonymous channel and EA payload channel are idealized models.
4. Weak (arity-based) Poseidon domain separation.
5. Identity width is a compile-time parameter (`idBits`): the CHUNKED
   circuits are compiled at 14 bits with depth-14 registration (up to
   16,384 registered voters — the measured N=10^4 result IS a true
   10^4-registered-voter proof), while the monolithic small/medium
   circuits keep 8 bits (their depth-4/6 trees cap voters at 16/64
   anyway). 10^5/10^6 electorates need re-instantiating the same
   templates at idBits/depth 17 or 20 (+6%/+13% constraints, projected
   in BENCHMARKS.md) plus a fresh dev setup.
6. Cast-as-intended out of scope (receipt-freeness hazard).
7. Groth16 proving requires the election parameters to match a compiled
   circuit variant exactly (small: 16 slots/depth 4, medium: 128
   slots/depth 6; boards beyond that use the chunked pipeline). The CLI
   resolves the variant from the parameters and rejects unmatched
   setups.
8. Tally-dispute evidence-incompleteness policy: an authority that
   supplies too few prior openings yields `Undetermined`, not
   `AuthorityFaulty` (see §8).
