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
| `R_i`    | the voter |
| `R_EA,i` | **only** the election authority (or threshold-shared among authority servers) |

Preprocessing publishes a binding-but-hiding commitment to both:

```text
h_i    = H_com(eid, i, vk_i, R_i, R_EA,i)      (Poseidon)
leaf_i = H_reg(eid, i, vk_i, h_i)              (Poseidon)
MR     = Merkle root over all leaf_i
```

A ballot encrypts `(eid, i, vk_i, m, R, sigma)` with
`sigma = Sign_sk_i(eid, i, m, R)` and is posted through an **anonymous
channel that preserves exact ballot bytes**.

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
8. The voter never receives `R_EA,i` — structurally: `VoterState` cannot
   carry it. (`preprocessing_tests`)
9. The judge resolves validity disputes using `R_EA,i` without giving it to
   the voter. (`dispute_tests`)
10. Chaff is rejected but indistinguishable from ordinary invalid ballots.
    (`chaff_tests`)

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
scripts/compile_circuits.sh small   # ~106k constraints
scripts/setup_groth16.sh small      # local ptau + zkey — DEV ONLY
cargo test                          # now includes Groth16 prove/verify
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

`circuits/main/filter_and_tally.circom` — `FilterAndTally(nB, nC, depth)`
proves the exact tally over the whole board (Groth16/BN254, Poseidon for all
in-circuit hashes, Schnorr-over-BabyJubJub signature verification in
circuit):

* every posted ciphertext — bound by a Poseidon-chain `bb_commitment` — is
  opened and evaluated;
* per-ballot validity (opening ∧ eid ∧ candidate ∧ signature ∧ hidden-nonce
  Merkle registration) is computed as **soft** 0/1 flags, so invalid
  ballots make flags false rather than the witness unsatisfiable;
* duplicates are resolved **after** validity (first-valid-counts; naive
  O(B²) Strategy A, with a sorted-witness Strategy B stubbed for scaling);
* the accumulated counts are constrained to equal the public
  `tally_counts`.

Public inputs: `eid_hash, MR, candidate_set_commitment, bb_commitment,
num_ballots, num_voters, duplicate_rule_id, pk_ea_commitment,
tally_counts[]` — and nothing else. A native relation checker
(`src/zk/mock_backend.rs`) mirrors the circuit constraint-for-constraint;
tests keep the two in agreement. Compile-time variants: small
(16 ballots / 3 candidates / depth 4, ≈106k constraints) and medium
(128 / 3 / 6) via `scripts/compile_circuits.sh {small|medium}`.

### ⚠️ Commitment-mode encryption prototype

The default ballot "encryption" is a **commitment-opening relation, not
public-key encryption**: `ct = Poseidon(plaintext_fields ‖ rho)`, with the
opening carried to the EA over a modeled private payload channel. This is
the acceptable first step for getting the exact relation to prove; the code
is structured for the intended swap-in: a native BabyJubJub-ElGamal +
Poseidon-pad hybrid backend already exists
(`crypto::encryption::elgamal_*`), and
`circuits/components/encryption_decrypt.circom` documents the exact circuit
replacement (`ss = sk_EA · C1`). Production encryption needs a full formal
treatment.

### ⚠️ Dev-only trusted setup

`scripts/setup_groth16.sh` runs powers-of-tau and phase-2 **locally, with no
ceremony**. Anyone holding the toxic waste can forge tally proofs. Groth16
setup is circuit-specific: recompile ⇒ redo setup. Never use these keys
outside development.

## 7. Threshold authority

A single authority knowing all `R_EA,i` is a trust point — it can
distinguish real from fake nonces. Two models are implemented:

* **Trusted-dealer Shamir** (`threshold/trusted_dealer.rs`): each `R_EA,i`
  is split into `k` shares, threshold `t`. Any `t` reconstruct; any `t−1`
  shares are information-theoretically independent of the secret.
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

* **Recorded-as-cast.** The anonymous channel preserves exact bytes, so a
  voter privately checks `BB.contains_exact_bytes(ballot.bytes)`
  (`check-recorded`). This is optional for coercion resistance — if a
  coercer demands to see a ballot, the voter shows the *fake* one. With an
  EA submission receipt `Sign_EA(eid, ballot_hash, timestamp)`, a missing
  ballot becomes attributable: valid receipt + absent bytes ⇒ `BoardFaulty`.
* **Tallied-as-recorded.** The judge privately receives the ballot opening,
  claimed `R_i`, signature, Merkle path — and `R_EA,i`, either from the EA
  or reconstructed from ≥ t threshold shares. It re-runs the validity
  checks and the duplicate rule and verifies the public tally proof.
  Verdicts: `AuthorityFaulty` / `VoterFaulty` / `BoardFaulty` /
  `Undetermined`. A fake nonce is detected here **privately** — the voter
  never learns `R_EA,i`, so nothing transferable is created.

Leakage discipline: the voter and the public never receive `R_EA,i`;
detailed verdicts may reveal real-vs-fake nonce usage and are therefore
**not** part of the coercion-resistance adversary view unless explicitly
modeled as leakage (demonstrated in `negative_attack_tests`).

**Cast-as-intended is out of scope** by design: evidence that a ballot
encodes a particular candidate is exactly the artifact that becomes a
receipt in a coercer's hands; it needs a separate treatment.

## 9. Repository layout

```text
src/
  main.rs        cr_dr CLI (all procedures independently invocable)
  crypto/        Poseidon (circomlib-compatible), Schnorr/BabyJubJub,
                 commitment-mode + ElGamal-hybrid encryption, Merkle, Shamir
  protocol/      setup, preprocessing (+ cut-and-choose), voting,
                 fake compliance, chaff, bulletin board, FilterAndTally
  threshold/     trusted-dealer Shamir + malicious-view simulator interface
  zk/            statement, witness builder, native relation checker,
                 circom input generation, snarkjs Groth16 backend
  disputes/      recorded-as-cast, tallied-as-recorded, judge verdicts
circuits/
  main/          FilterAndTally template + small/medium instantiations
  components/    poseidon_hashes, merkle_membership, signature_verify,
                 encryption_decrypt, ballot_validity, duplicate_first_valid,
                 tally_accumulator
  input_examples/  small_valid_input.json, fake_before_real_input.json
scripts/         install_circom_deps, compile_circuits, setup_groth16,
                 prove, verify
tests/           12 suites: protocol correctness + security invariants
```

## 10. Design notes & compatibility

* All circuit-facing values are BN254 scalar field elements; field elements
  serialize as decimal strings (circom's input format).
* Native Poseidon is `light-poseidon` (circomlib-parameter-compatible,
  pinned by test vectors against circomlibjs).
* BabyJubJub points are stored in **circomlib coordinates**
  (`168700·x² + y² = 1 + 168696·x²y²`); arithmetic maps internally to
  arkworks' isomorphic `a = 1` form (`x_ark = √168700 · x_circom`).
* The signature is Schnorr over BabyJubJub with a Poseidon challenge,
  verified in-circuit with circomlib's `escalarmulany`/`escalarmulfix`/
  `babyjub` gadgets and the standard `Base8` generator — the native
  verifier and the circuit implement the identical equation.
* Poseidon arities double as (weak) domain separation between `H_com` (6),
  `H_reg` (5), the signature message hash (4) and the ciphertext
  commitment (10); production needs explicit domain tags.
* Per-ballot internal statuses (`InternalBallotEvaluation`) are
  test/debug-only, deliberately non-serializable, and never published.

## 11. Known limitations (summary)

1. Commitment-mode "encryption" is not PKE (loud warning above).
2. Dev-only Groth16 setup; no ceremony.
3. Cut-and-choose models the audit intuition, not a malicious VSS/DKG.
4. The anonymous channel and EA payload channel are idealized models.
5. Weak (arity-based) Poseidon domain separation.
6. O(B²) in-circuit duplicate check — fine at 16–128 ballots; sorted-witness
   strategy stubbed for scaling.
7. Cast-as-intended out of scope (receipt-freeness hazard).
8. Groth16 proving assumes the small circuit shape; boards larger than the
   compiled `NUM_BALLOTS` need the medium/larger variant.
