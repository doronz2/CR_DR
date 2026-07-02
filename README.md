# CR-DR — Coercion-Resistant Voting with Private Dispute Resolution

Rust + Circom/Groth16 **research reference implementation** of the
construction from the paper *"Coercion-Resistant Voting with Private Dispute
Resolution"*.

> **THIS IS A RESEARCH PROTOTYPE, NOT PRODUCTION CRYPTOGRAPHY.**
> It implements the **construction** — setup, preprocessing, voting, fake
> compliance, chaff, FilterAndTally, the ZK tally proof and private dispute
> resolution. It deliberately does **not** implement the coercion-resistance
> real/ideal experiment, hybrid experiments, or any adversary game code.

## Protocol overview

Parties: voters `V_i`, an election authority `EA` (optionally thresholded),
an append-only public bulletin board `BB`, public auditors, and a **private
judge** `J` for dispute resolution.

Preprocessing gives voter `i` a signing keypair `(sk_i, vk_i)` and a nonce
`R_i`. The authority holds a **hidden authority nonce** `R_EA,i`. Public
registration data:

```text
h_i    = H_com(eid, i, vk_i, R_i, R_EA,i)      (Poseidon)
leaf_i = H_reg(eid, i, vk_i, h_i)              (Poseidon)
MR     = Merkle root over all leaf_i           (Poseidon tree)
```

A ballot encrypts `(eid, i, vk_i, m, R, sigma)` with
`sigma = Sign_sk_i(eid, i, m, R)`. A ballot is **valid** iff it decrypts,
has `m` in the candidate set, its signature verifies, and the hidden nonce
relation holds (`h`/`leaf` recomputed with `R_EA,i` is in `MR`). Duplicates
are handled **only after** validity, with **first-valid-ballot-counts**.

**Fake compliance.** A coerced voter surrenders their *real* `sk_i` and a
*fake* nonce `R*`, and signs whatever the coercer demands. The coercer can
verify the signature — it is genuinely valid — but cannot test `R*` against
the registration commitment, because that requires `R_EA,i`, which the voter
**never receives**. The fake ballot fails the hidden nonce check inside
FilterAndTally; the voter's real ballot goes in over an anonymous channel.
**Critical invariant:** invalid ballots do not consume the voter's slot, so
a fake ballot posted *before* the real one cannot block it
(`tests/fake_compliance_tests.rs`, `tests/negative_attack_tests.rs`).

**Chaff.** Anyone may submit chaff ballots — syntactically perfect ballots
for unregistered identities. They are rejected exactly like fake-compliance
ballots (same public shape, same internal rejection class, no marker), which
gives fake ballots a crowd to hide in.

**Anonymous channel & recorded-as-cast.** The modeled anonymous channel
hides the sender and **preserves exact ballot bytes**; a voter can privately
check `BB.contains_exact_bytes(real_ballot.bytes)`. This check is optional
and must never be exposed to the coercer.

## The ZK tally proof

`circuits/main/filter_and_tally.circom` proves the **exact** FilterAndTally
computation over the *whole* bulletin board (Groth16 over BN254, Poseidon
for all in-circuit hashes, Schnorr/BabyJubJub signature verification in
circuit):

* every posted ciphertext (bound by a Poseidon chain commitment
  `bb_commitment`) is opened and evaluated;
* validity = opening ∧ eid ∧ candidate-in-C ∧ signature ∧ hidden-nonce
  Merkle registration — all evaluated as *soft* flags;
* duplicates resolved **after** validity (first-valid-counts, naive O(B²)
  Strategy A; a sorted-witness Strategy B is stubbed as TODO);
* the accumulated counts equal the public `tally_counts`.

Public inputs: `eid_hash, MR, candidate_set_commitment, bb_commitment,
num_ballots, num_voters, duplicate_rule_id, pk_ea_commitment,
tally_counts[]`. The proof reveals **nothing** about which ballots were
valid or counted, voter identities, rejection reasons, plaintexts, `R_i`,
`R_EA,i` or signatures (`tests/groth16_integration_tests.rs`).

The native relation checker (`src/zk/mock_backend.rs`) mirrors the circuit
constraint-for-constraint and the tests keep them in agreement.

### ⚠️ Commitment-mode encryption prototype

The current encryption backend is a **commitment-mode prototype, not full
public-key encryption**: `ciphertext = Poseidon(plaintext_fields || rho)`,
with the opening carried to the EA over a modeled private payload channel.
This is the spec'd first step to make the exact tally relation provable; a
native BabyJubJub-ElGamal + Poseidon-pad hybrid backend is already
implemented (`crypto::encryption::elgamal_*`) and
`circuits/components/encryption_decrypt.circom` documents the exact circuit
swap (`ss = sk_EA · C1`). Production encryption needs a full formal
treatment (key validation, CCA transform, etc.).

### ⚠️ Dev-only trusted setup

`scripts/setup_groth16.sh` runs powers-of-tau and phase-2 **locally with no
ceremony**. Anyone with the toxic waste can forge proofs. Groth16 setup is
circuit-specific: recompile ⇒ redo setup. Never use these keys outside
development.

## Threshold authority

* **Model 1 — trusted-dealer Shamir** (`threshold/trusted_dealer.rs`): every
  `R_EA,i` is split into `k` shares with threshold `t`; any `t` reconstruct,
  and any `t−1` shares are information-theoretically **independent of the
  secret** — which is exactly why the malicious-view simulator below can
  sample them without knowing `R_EA,i`.
* **Model 2 — malicious preprocessing view model**
  (`threshold/malicious_view_model.rs`): a `ThresholdViewSimulator` trait.
  The simulation target is the **honest-generated part of the corrupted
  authorities' view** (honest messages, honest commitments, honest public
  transcript, shares delivered from honest authorities). The adversary's own
  corrupted-party inputs and messages are passed in as
  `AdversaryAuxiliaryState` — they are *context*, never simulated output.
  The simulator never receives any `R_EA,i`.

Cut-and-choose preprocessing (`preprocess_voter_cut_and_choose`) models the
audit intuition: `q` candidate pairs, `q−1` audited, the unopened pair
becomes the voting pair; a dealer corrupting one pair survives with
probability ≈ `1/q` (tested). **This is not a full malicious VSS/DKG.**

## Private dispute resolution

* **Recorded-as-cast**: exact byte matching on `BB`, or an EA submission
  receipt `Sign_EA(eid, ballot_hash, timestamp)`; a valid receipt plus
  missing bytes ⇒ `BoardFaulty`.
* **Tallied-as-recorded**: the judge privately receives the ballot opening
  and `R_EA,i` (directly or reconstructed from ≥ t threshold shares) and
  re-runs checks 1–7 (opening, signature, `h`, `leaf`, `MR`, duplicate
  status, public tally proof). Verdicts: `AuthorityFaulty`, `VoterFaulty`,
  `BoardFaulty`, `Undetermined`.

Leakage discipline: the voter **never** receives `R_EA,i` (so it cannot be
transferred to a coercer as a receipt), the public never receives it, and
**detailed judge verdicts are not part of the coercion-resistance adversary
view** unless explicitly modeled as leakage — a public verdict would reveal
evasion status (`tests/negative_attack_tests.rs`).

**Cast-as-intended is out of scope.** Evidence that a ballot encodes a
particular candidate is precisely the kind of transferable artifact that
becomes a *receipt* in a coercer's hands; it needs a separate treatment
(e.g. Benaloh-style challenges with careful deniability analysis) and is
deliberately not implemented.

## Repository layout

```text
src/
  crypto/        Poseidon (circomlib-compatible), Schnorr/BabyJubJub,
                 commitment-mode + ElGamal-hybrid encryption, Merkle, Shamir
  protocol/      setup, preprocessing (+ cut-and-choose), voting,
                 fake compliance, chaff, bulletin board, FilterAndTally
  threshold/     trusted-dealer Shamir + malicious-view simulator interface
  zk/            statement, witness builder, native relation checker,
                 circom input generation, snarkjs Groth16 backend
  disputes/      recorded-as-cast, tallied-as-recorded, judge verdicts
circuits/
  main/          FilterAndTally template + small (16,3,4) / medium (128,3,6)
  components/    poseidon_hashes, merkle_membership, signature_verify,
                 encryption_decrypt, ballot_validity, duplicate_first_valid,
                 tally_accumulator
  input_examples/  small_valid_input.json, fake_before_real_input.json
scripts/         install_circom_deps, compile_circuits, setup_groth16,
                 prove, verify
tests/           12 test suites incl. security-invariant negative tests
```

## Building and running

Prerequisites: Rust (edition 2021; a recent toolchain — some transitive
deps require ≥ 1.85), and for the ZK pipeline Node.js ≥ 18 plus the circom 2
compiler.

```bash
cargo test                         # native protocol + relation tests
                                   # (Groth16 tests skip if artifacts absent)
scripts/install_circom_deps.sh     # circom 2 (cargo), snarkjs + circomlib (npm)
scripts/compile_circuits.sh small  # ~106k constraints
scripts/setup_groth16.sh small     # DEV-ONLY ptau + zkey (few minutes)
cargo test                         # now including Groth16 prove/verify
cargo run --bin cr_dr_demo         # end-to-end demo election
```

`cargo run --bin gen_example_inputs` regenerates the checked-in example
inputs; `scripts/prove.sh circuits/input_examples/small_valid_input.json`
and `scripts/verify.sh` drive snarkjs directly.

## Design notes & compatibility

* All circuit-facing values are BN254 scalar field elements; field elements
  serialize as decimal strings (circom's input format).
* Native Poseidon is `light-poseidon` (circomlib parameter-compatible;
  pinned by test vectors against circomlibjs).
* BabyJubJub points are stored in **circomlib coordinates**
  (`168700·x² + y² = 1 + 168696·x²y²`); arithmetic maps to arkworks'
  isomorphic `a = 1` form (`x_ark = √168700 · x_circom`) internally.
* The signature is Schnorr over BabyJubJub with a Poseidon challenge,
  verified inside the circuit with circomlib's `escalarmulany`/
  `escalarmulfix`/`babyjub` gadgets and the standard `Base8` generator.
* Poseidon arities double as (weak) domain separation between `H_com` (6),
  `H_reg` (5), the signature message hash (4) and the ciphertext commitment
  (10); a production design should add explicit domain tags.
* `InternalBallotEvaluation` (per-ballot statuses) is test/debug only, never
  serialized, never public.

## Known limitations (summary)

1. Commitment-mode "encryption" is not PKE (see the loud warning above).
2. Dev-only Groth16 setup; no ceremony.
3. Cut-and-choose models the audit intuition, not a malicious VSS/DKG.
4. The anonymous channel and the EA payload channel are idealized models.
5. Weak (arity-based) Poseidon domain separation.
6. O(B²) in-circuit duplicate check — fine for 16–128 ballots; the
   sorted-witness strategy is stubbed for scaling.
7. Cast-as-intended is out of scope by design (receipt-freeness hazard).
