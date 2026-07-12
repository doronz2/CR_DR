# HANDOFF — admission-paths work, status of chunks A–E

## UPDATE (2026-07-09, post-checkpoint)

All caveats below are RESOLVED, and a second wave of work landed after
the `d137a71` checkpoint:

* **Soft-safe tally totality** (`7eb60c8`): in-circuit S-canonicity flag
  (fixes a real voter-triggered unsat/DoS via S+l signature malleation),
  registration-time vk validation, `tests/soft_safety_tests.rs` (7 DoS
  tests incl. a real-Groth16 poisoned-board proof).
* **Public chunked-transcript verifier + leakage fix** (`7d512bb`):
  `verify_chunked_public_transcript` (public data + proof objects only;
  13 malicious-transcript tests); the per-chunk public products pp_k/qq_k
  (whose ratio leaked record information) are replaced by HIDING
  running-product commitment chains with in-circuit final equality —
  see CHUNKED_TALLY_DESIGN.md "Public values and leakage".
* **Dispute verdicts** (`593b428`): `NoAuthorityFault` added +
  `external_verdict()` coarsening (VoterFaulty -> NoAuthorityFault
  externally), matching the paper's five-verdict model.
* **Measured N=10^4 scalability result**: 20,480 ballots, 321 proofs,
  847.5 s prove / 67.1 s verify-all on the finalized circuits
  (BENCHMARKS.md "Measured scalability result"; commit `593b428`), with
  a compiled depth-14 sizing variant (1,493,181 constraints) for honest
  widened-parameter projections at 10^5/10^6.
* All Groth16 zkeys regenerated for the final circuits (small 144,339;
  medium 1,235,915; vchunk128 1,245,383; srun128 95,378; tsum
  1,668–48,000). Full suite: **129 passed / 0 failed**. Benchmark tables
  in BENCHMARKS.md and the paper's evaluation re-measured on these
  circuits; the two previously-estimated cast numbers are now measured
  (seal 0.62 ms, prove_cast 135 ms, verify 208 ms).

* **External review round (2026-07-10)**: five verified findings fixed —
  (1) CLI `submit` now generates and attaches pi_cast (proofless Path-1
  submissions were unconditionally dropped by Clean; verified end-to-end:
  submit -> flush -> admit-board admits 2/2 -> tally -> prove -> verify);
  (2) the d14 sizing variant is honestly labeled DEPTH-ONLY (identities
  remain 8-bit everywhere; a 10^4-registered-voter circuit is NOT yet
  implemented — the measured result is a 10^4-BOARD result);
  (3) the tallied-as-recorded judge RECOMPUTES the duplicate predicate
  from the EA openings store instead of trusting authority-supplied
  evaluations (fabricated prior opening -> AuthorityFaulty, tested);
  (4) Path-1 recorded-as-cast adjudication now requires a VERIFYING
  pi_cast at the matching board index, not just entry bytes;
  (5) CLI prove/verify/dispute resolve the circuit shape from the
  election parameters and reject unmatched setups instead of silently
  using the small circuit. Suite: **131 passed / 0 failed**.

* **Second review round (2026-07-10)**: `check-recorded` is now
  PROOF-AWARE (RECORDED with verifying pi_cast / PRESENT BUT NOT
  ADMISSIBLE / NOT RECORDED — mirrors dispute adjudication); README §8
  rewritten for the proof-aware recorded-as-cast semantics and the
  five-verdict model; README §11 known-limitations de-staled (O(B²)
  duplicate wording, small-shape assumption, dangling not-PKE warning,
  pre-soft-safe gadget description) and now names the 8-bit identity
  width as THE next scalability gap; the tally-dispute
  evidence-incompleteness policy (missing prior openings ⇒ Undetermined,
  not AuthorityFaulty; fabricated openings ⇒ AuthorityFaulty) is stated
  explicitly in code docs, README §8, and the paper's dispute model.

* **Identity widening (2026-07-12, `45eabdf`)**: idBits is now a
  template parameter. Chunked circuits compiled at 14-bit ids +
  depth-14 registration (16,384-voter capacity; vchunk128 1,493,956 /
  srun128 96,920 constraints); monolithic stays 8-bit (structurally
  unchanged). The measured N=10^4 result is now a TRUE
  10^4-registered-voter proof: 10,000 voters, 20,480 ballots, 321
  proofs — 1000.6 s prove / 67.6 s verify-all / 1.70 GB per worker
  (matching the earlier x1.2 depth-only projection of ~1017 s). The
  board-vs-voter caveat is gone; 10^5/10^6 remain projections at
  idBits/depth 17 and 20 (+6%/+13%). 131 tests green.

The original checkpoint snapshot follows (historical).

---

Snapshot taken at commit `5561f0f` ("CAST-ZK ballot format + admitted-board
submission model"). Working tree clean; `cargo check` passes; full test
suite **109 passed / 0 failed** (includes real Groth16 prove+verify for
the small tally circuits and the cast circuit). Chunks F–J not started.

Toolchain note (historical): one background process may still be
regenerating the LARGE Groth16 zkeys (medium, medium_naive, vchunk128)
under `build/` (untracked) — since completed, see the UPDATE above.
Nothing in `cargo test` depends on them; only the
`groth16_medium`/`chunked` benchmark groups do.

---

## A. Admission abstraction: BB_raw / BB_adm, two admission paths — DONE

1. **Files changed**: `src/protocol/admission.rs` (new),
   `src/protocol/bulletin_board.rs`, `src/protocol/filter_and_tally.rs`,
   `src/protocol/mod.rs`, `src/zk/{witness,statement,chunked}.rs`,
   `src/main.rs` (CLI: `admit-board`, `ea-submit`, path-split
   `dispute-recorded`; file layout `public/admitted.json`,
   `authority/openings.json`, `public/cast_proofs.json`),
   `src/bin/{gen_example_inputs,prove_chunked}.rs`, all test files,
   `benches/prover.rs`.
2. **Implemented**: `BulletinBoard` = BB_raw (raw `(com, ct_open)`
   entries + `RawSubmission` carrying optional pi_cast);
   `AdmittedBoard` = BB_adm (commitment list, THE tally input);
   `AdmittedOpenings` (EA-private, aligned with BB_adm). The entire tally
   pipeline (filter_and_tally, witness builder, statement, chunked
   pipeline, dispute judge) consumes `(BB_adm, openings)` and is
   admission-path independent. Paths are never mixed implicitly;
   `admitted_from_ballots` is the explicit test/bench helper modeling an
   already-admitted board.
3. **Remains**: nothing for the abstraction itself.
4. **Tests exist**: yes (all suites rewired; Path-1 e2e in
   `tests/cast_tests.rs`; Path-2 in `tests/dispute_tests.rs`).
5. **Tests pass**: yes (109/109).
6. **Known issues**: none.

## B. Public cast-ZK path: (com, ct_open, pi_cast), public cleaning — DONE

1. **Files changed**: `circuits/main/cast_proof.circom` (new),
   `circuits/main/filter_and_tally_cast.circom` (new, 6,095 constraints,
   15 public inputs), `src/crypto/encryption.rs` (BabyJubJub-ElGamal +
   Poseidon-pad hybrid: `cast_encrypt`/`cast_decrypt`, `CastCiphertext`,
   `CastSecret`, `sample_rho_enc`), `src/zk/cast.rs` (new:
   `prove_cast`, `verify_cast_entry`, `cast_relation_check_native`,
   input/publics serialization), `src/protocol/vote.rs` (`seal_ballot`,
   shared by real/fake/chaff), `src/protocol/admission.rs` (`clean`,
   `ea_open_admitted`), `src/types.rs` (`Ballot`/`PublicBallot` in the
   new format), `tests/cast_tests.rs` (new).
2. **Implemented**: pi_cast proves com and ct_open open to the SAME
   (opening, r_com) with rho_enc != 0; all-hard (failing proof = public
   rejection pre-tally); verified publicly, NEVER in the tally circuit;
   `Clean(BB_raw)` keeps exactly valid-pi_cast entries, deterministic and
   publicly recomputable; fake-compliance and chaff entries pass
   admission and remain in BB_adm (tested). Proof binding checks: exact
   public-input equality + Groth16 verify + C1 subgroup/non-identity.
3. **Remains**: the OPTIONAL pi_cast strengthening (public
   well-formedness: curve/range checks of vk/signature fields, candidate
   range, signature under committed vk) is NOT implemented — documented
   as an option; current pi_cast is the required minimum. Deliberately no
   hidden validity in pi_cast (as specified).
4. **Tests exist**: yes — valid accepted; tampered com / tampered
   ct_open / tampered proof / transplanted proof rejected; fake and
   chaff have valid pi_cast; Path-1 Clean e2e (mixed board with tampered
   + proofless entries; tally binds the recomputed BB_adm); byte-level
   leak regression (no opening/R/R_EA/candidate/validity/sorted-record
   values in any public bytes).
5. **Tests pass**: yes (8/8 in cast_tests, with real Groth16).
6. **Known issues**: none.

## C. EA-mediated private submission + EA receipt — DONE

1. **Files changed**: `src/protocol/admission.rs` (`ea_admit_private`,
   `EaAdmissionState`), `src/disputes/recorded_as_cast.rs` (receipt =
   `Sign_EA(eid, com, timestamp)`; `ea_issue_admission_receipt`,
   `verify_receipt`, `adjudicate_admission_receipt`,
   path-1 `adjudicate_recorded_as_cast` over raw bytes),
   `src/main.rs` (`ea-submit`), `tests/dispute_tests.rs`.
2. **Implemented**: voter privately submits (com, opening, r_com); EA
   checks ONLY admission-level consistency (com opens) and returns the
   signed receipt; EA accumulates/post BB_adm; receipt certifies
   admission only (never hidden validity/counted status). Dispute: valid
   receipt + com absent from posted BB_adm => AuthorityFaulty (EA-posts
   model; would be BoardFaulty with a separate board operator — noted in
   code docs).
3. **Remains**: nothing required. (Posting-model variants beyond
   EA-posts are documentation-only.)
4. **Tests exist**: yes — receipt round-trip; missing-posted-commitment
   => AuthorityFaulty; honest posting => complaint unfounded;
   **coercion condition**: fake-nonce ballot receives a structurally
   identical receipt to a real one and both are admitted.
5. **Tests pass**: yes.
6. **Known issues**: none.

## D. Tally relation over admitted commitments — DONE

1. **Files changed**: `circuits/components/ballot_validity.circom` (hard
   active-gated `com === Poseidon(pt || rho)`; opening removed from the
   soft conjunction), `circuits/components/signature_verify.circom`
   (SOFT-SAFE Schnorr: soft Edwards on-curve flags, Base8 muxing,
   `CompleteEscalarMul` — complete Edwards double-and-add replacing
   circomlib's torsion-unsafe Montgomery ladder for c·A, strict S
   decomposition with soft top-zero flag), `src/zk/mock_backend.rs`
   (mirrors both changes; `eval_row` hard-open), `src/zk/witness.rs`
   (rows from the openings store; dummy-substitution policy REMOVED —
   obsolete under hard opening + soft-safe gadget),
   `src/zk/{statement,chunked}.rs` (statement/bb-chain over BB_adm coms).
2. **Implemented**: public input = BB_adm commitment chain + Reg/MR +
   params + candidate-set commitment + duplicate rule id + tally; witness
   per admitted commitment = (opening, r_com, R_EA-side values); hard
   check `com_j = H_ballot_com(opening_j, r_com_j)`; soft/private
   validity (eid, in-range, candidate, signature, indexed Reg row, vk
   match, hidden nonce); records `(valid, id, pos, m)` sorted by
   `(-valid, id, pos)`, first-valid-per-identity counting — all
   unchanged from the pre-existing relation. Signature stays checked
   in-circuit (the "unless certified by pi_cast" optimization is NOT
   taken, consistent with B.3).
3. **Remains**: LARGE circuit artifacts (medium, medium_naive,
   vchunk128) grew ~20% (medium now 1,202,635 constraints) and their
   zkeys must be regenerated (`scripts/setup_groth16.sh medium|
   medium_naive|vchunk128`) — a background job may already have finished
   this; check `build/circuits/*_verification_key.json` freshness vs the
   r1cs. Until then the `groth16_medium` and `chunked` BENCHMARK groups
   fail with "Invalid witness length" (exact error recorded below).
   Small/small_naive/cast artifacts are rebuilt and green. Headline
   benchmark tables in BENCHMARKS.md predate the format change (flagged
   inline; ~1.2x scale note included).
4. **Tests exist**: yes (mock-vs-circuit agreement, hard-open
   inconsistency = hard error, groth16 integration incl. rapidsnark
   cross-check, chunked native suite).
5. **Tests pass**: yes — `cargo test` does not depend on the large
   artifacts.
6. **Known issues**: benchmark-only, until the zkey regeneration
   completes:
   `snarkJS: Error: Invalid witness length. Circuit: 1009425, witness: 1202577`
   (stale `filter_and_tally_medium.zkey` vs recompiled circuit). Also
   note: criterion group-setup code runs even for name-filtered-out
   groups, so ANY `cargo bench --bench prover` invocation touches the
   medium artifacts.

## E. Paper / evaluation language updates — DONE

1. **Files changed** (paper repo `~/Documents/CR_DR`, NOT this git
   repo): `sections/construction.tex` (new subsection "Ballot submission
   and admission", label `sec:admission`: BB_adm definition, Path 1 with
   Clean and no-hidden-validity statement, Path 2 with receipt semantics
   and the coercion condition, common tally proof),
   `sections/evaluation.tex` (paragraph "Admission paths and benchmark
   scope": tally benches admission-path independent, Path-1 per-voter
   costs, Path 2 = signatures only), `sections/references_manual.tex`
   (earlier: Groth16/Poseidon/Batcher/SnarkPack/iden3 entries),
   `main.tex` (evaluation input).
2. **Implemented**: the requested two-path protocol description and the
   benchmark-scope clarifications; PDF builds clean (33 pp., 0 errors).
3. **Remains**: the per-voter cast numbers in evaluation.tex are partly
   estimates (seal ≈0.9 ms MEASURED; prove_cast ≈0.15 s and verify
   ≈0.2 s ESTIMATED from test timings) — replace with `cast` bench-group
   means once the large zkeys are rebuilt (benchmarking currently
   paused). The paper repo is not under this git remote; changes exist
   on disk only.
4. **Tests exist**: n/a (LaTeX); build = the check.
5. **Tests pass**: `pdflatex` x2 clean, all references resolved.
6. **Known issues**: none.

---

## Command results at snapshot time

- `git status --short` — empty (clean tree at `5561f0f`).
- `git diff --stat` — empty.
- `cargo check` — passes (no errors, no warnings).

## Not done (explicitly out of scope per instructions)

- Chunks F–J: not started.
- No further benchmarks run; no design changes beyond A–E.
