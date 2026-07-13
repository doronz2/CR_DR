# Tier-3 decentralized proving (coSNARK / co-circom)

This document describes the Tier-3 decentralized prover and — with equal
care — draws the line between what is **fully decentralized**, what is
**still centralized in this integration**, and what is **cryptographically
real but architecturally simulated** in the localhost benchmark.

## Goal

No single party ever reconstructs, in the clear, any of: the full tally
witness, the decrypted ballot openings, the authority nonce `R_EA`, the
per-ballot validity records, the sorted records, the duplicate structure,
the partial tallies, the grand-product values, or the accepted identities.
The tally proof is produced by an MPC among several parties over a
**secret-shared** witness, and only the final tally is revealed.

## Two entry points and their honest status

- **`prove_tier3`** — the phase-1 *validity* relation, **fully
  decentralized in MPC INCLUDING witness extension**: co-circom extends the
  witness on secret shares (no party sees openings, R_EA, validity flags,
  or identities) and proves collaboratively. This is the strongest
  fully-working Tier-3 artifact (measured; verified). It does not by itself
  cover duplicates/tally.

- **`prove_tier3_full`** — the FULL monolithic relation (validity → records
  → sort → duplicate counting → tally) as ONE circuit whose entire witness
  — records, sorted records, duplicate structure, partial tallies, tally —
  is internal (nothing centrally constructed by design; the tally is the
  circuit's public output). Two modes, because of a co-circom limitation
  (next section):
  - `--mode full-mpc` — the genuine Tier-3 path (decentralize witness
    extension AND proving). **Currently blocked** by a co-circom v0.10.0
    bug; the command reports this precisely rather than faking success.
  - `--mode proving-mpc` — decentralizes only the collaborative PROVING,
    over a witness computed by a single snarkjs process. It **completes and
    verifies with the correct revealed tally**, demonstrating that the full
    relation's collaborative proving works; but the central witness step
    sees the records/tally, so this mode does NOT decentralize witness
    extension (loudly flagged at runtime).

## co-circom v0.10.0 limitation (full-relation witness extension)

The full monolithic circuit is proven CORRECT independently of MPC: plain
snarkjs computes a satisfying witness and its Groth16 proof verifies with
the right tally, and co-circom's collaborative PROVING over a
(snarkjs-)split witness verifies with the right tally. The gap is
co-circom's MPC WITNESS EXTENSION of the duplicate/tally stage: on the full
circuit it produces an unsatisfying witness under `-O2` (proof fails to
verify) and panics/hangs under `-O1`/`-O0`, for both the sorted-network
(Strategy B) and the naive-scan (Strategy A) duplicate circuits, at
nb = 4/16/128. The phase-1 validity relation — same gadgets minus the
duplicate/tally stage — extends and proves in MPC without issue. So this is
a limitation of the experimental, un-audited co-circom MPC-VM on the
duplicate/tally circuitry, not of our circuit or the design. Fully
decentralizing the whole relation's witness extension awaits a co-circom
fix (or an MPC witness-extension backend that handles those gadgets).

## Why the full relation, not the chunked pipeline

The chunked pipeline (CHUNKED_TALLY_DESIGN.md) exists to keep each
single-prover circuit small. But its phases are glued by a **central
orchestrator** (`build_chunked_tally`) that computes, in the clear, the
per-ballot records, the GLOBAL sort, the boundary commitments, the
grand-product accumulators and the partial tallies, then feeds them as
witness to the next phase. That central construction is exactly what full
Tier-3 must eliminate — so the chunked pipeline is structurally the wrong
vehicle. Making it decentralized would require an MPC oblivious sort plus
transport of secret-shared records between the phase circuits, which
co-circom's independent-circuit model does not provide.

The **monolithic** relation has no such glue: validity records, the
Batcher sort, the first-valid duplicate counting and the tally accumulation
are all INTERNAL wires of one circuit. Proving that circuit in MPC extends
its entire witness on secret shares, so none of those intermediates is ever
constructed centrally or seen by any party. `prove_tier3_full` therefore
does NOT call `build_chunked_tally` at all. The cost is circuit size: a
monolithic circuit for a board of `B` ballots is `O(B)` in ballots plus the
`O(B log^2 B)` sort, so the trusted-setup power of tau bounds `B` (the
compiled `filter_and_tally_medium_mpc` holds `nb = 128`; reaching
`B ≈ 2·10^3` needs a larger ceremony — see BENCHMARKS.md "Tier-3").

## How it works

The tally relation is the existing Circom/Groth16 relation, unchanged. We
prove it with **TACEO co-circom** (v0.10.0), a collaborative-SNARK tool
that (1) extends the Circom witness *inside* MPC from secret-shared inputs
and (2) runs collaborative Groth16 over the shared witness, emitting one
**standard** Groth16 proof that verifies under the ordinary verification
key. We drive the `co-circom` binary as a subprocess (`src/zk/tier3.rs`);
we reuse the *same* `.r1cs` and the *same* snarkjs `.zkey` as Tier-1.

MPC backend: **REP3** (replicated 3-party, honest-majority, semi-honest).

### The R_EA change (why no party reconstructs it)

Tier-1 feeds `R_EA` into the circuit as one field per ballot, which forces
*some* party to run `shamir::reconstruct` and see it. The Tier-3 circuit
`ValidityChunkMpc` instead takes the **two Shamir shares** of each ballot's
`R_EA` as two SEPARATELY-NAMED inputs and reconstructs `R_EA`
**in-circuit** via Lagrange interpolation with public coefficients
(`components/lagrange_combine.circom`: for t=2, `R_EA = 2·s₁ − s₂`). This
is linear, so it adds **zero** R1CS constraints (`vchunkmpc128` and Tier-1
`vchunk128` are both 1,493,956 constraints). Under MPC witness extension
each authority contributes its own secret-shared share; the combine runs
on shares; `R_EA` exists only as an MPC-shared value.

### The provider partition (why no party sees the other's inputs)

co-circom's `merge-input-shares` combines inputs **by name**, on shares,
without reconstructing any plaintext union. We exploit this with three
independent input providers per validity chunk
(`tier3::chunk_providers`):

| provider | contributes | never sees |
|---|---|---|
| opening | public inputs, ballot openings (`ct`, `pt`, `rho`), registration rows/paths, `rc_blind` | any `R_EA` share |
| authority 1 | ONLY `r_ea_share_a` (Shamir index 1) | authority 2's share, the openings |
| authority 2 | ONLY `r_ea_share_b` (Shamir index 2) | authority 1's share, the openings |

Each provider `split-input`s only its own file; per party the co-indexed
shares are merged; the MPC witness extension then evaluates the whole
relation (including the R_EA combine and the per-ballot validity/record
computation) on shares. The public output `rc` is a hiding commitment to
the records, so per-ballot validity flags, candidate choices, and accepted
identities are computed in MPC and never revealed.

### Pipeline placement

The chunked pipeline (CHUNKED_TALLY_DESIGN.md) has three circuit families:
phase-1 **validity chunks**, phase-2 **sorted-run chunks**, and a
**tally-sum** proof. `ValidityChunkMpc` has public inputs byte-identical to
the Tier-1 `ValidityChunk`, so a Tier-3 validity proof drops into the exact
same public transcript and aggregate verifier.

## What is decentralized vs centralized vs simulated

### `prove_tier3` (validity relation) — fully decentralized, verified

Both witness extension AND proving are in 3-party MPC:

- **The witness** — extended inside MPC; never materialized in any party.
- **`R_EA`** — reconstructed in-circuit from separate per-authority shares;
  never a plaintext anywhere.
- **Ballot openings** — enter as provider input shares; MPC sees only shares.
- **Per-ballot validity flags, candidate choices, accepted identities** —
  computed in MPC, emitted only as the hiding record commitment `rc`.
- **The Groth16 proof** — collaborative proving over the shared witness;
  verifies under the standard key.

This is the strongest artifact. It does not, alone, cover the sort /
duplicate / tally.

### `prove_tier3_full` (full relation) — status by mode

The full monolithic circuit is DESIGNED so nothing is centrally
constructed (records, sorted records, duplicate structure, partial
tallies, tally are all internal wires; only the tally is revealed). What
is actually achieved depends on the mode, because co-circom v0.10.0 cannot
MPC-extend the duplicate/tally stage (see the limitation section above):

- `--mode full-mpc` (the intended complete Tier-3): would decentralize
  everything, but **does not complete** on co-circom v0.10.0 — the command
  reports the limitation. The circuit is nonetheless proven correct
  (snarkjs; and co-circom collaborative proving over a split witness).
- `--mode proving-mpc` (completes, verified): the Groth16 PROVING is
  decentralized over witness shares and reveals the correct tally, but the
  witness is extended by ONE snarkjs process, so THAT step sees the
  records/sorted-records/duplicates/tally. So with this mode the *proving*
  is decentralized but the *witness extension* is not.

Other non-decentralized pieces (both drivers):

- **Board size bound.** The monolithic circuit holds `nb = 128` ballots on
  the compiled ceremony; larger boards need a larger power-of-tau. A *scale*
  limit, not a leak.
- **Threshold decryption of `ct_open`.** Path 1 avoids it (the voter
  provides its own opening). A Path-2 deployment would need a
  threshold-decryption MPC to produce opening *shares* — not implemented.
- **The benchmark harness knows everything.** The driver generates a
  synthetic election, so that process holds all secrets (it created them) —
  a property of the *benchmark generator*, not of the co-circom parties. A
  real deployment has each provider generate its own inputs independently.

### Cryptographically real but architecturally SIMULATED (localhost)

Running the three REP3 parties as three processes on one machine:

- **Real:** the secret-sharing math (each party's `.shared` files and
  memory are information-theoretically uninformative about the witness),
  the MPC protocol correctness, the standard-Groth16 interop, and the
  actual TCP+TLS (rustls) transport.
- **Simulated:** independent trust domains and non-collusion. One OS
  operator runs all three processes and can read every process's memory,
  so the "no single party sees the witness" guarantee is a property of a
  DEPLOYMENT on independent infrastructure — it is *outside* the model a
  localhost run can establish. The example TLS keys are demo keys generated
  together; real parties hold their own keys in their own domains.

### Library maturity caveat

co-circom is self-described as **experimental and un-audited**; its REP3
backend is **honest-majority, semi-honest** (a malicious party could
deviate). This is a credible research/demo integration, not a production
security boundary.

## Measured (M3 Max; localhost REP3; see BENCHMARKS.md "Tier-3")

Two chunk widths, both proved + verified end-to-end in 3-party REP3
(split → merge → MPC witness extension → MPC Groth16 → verify), each a
standard proof bound to the same statement as Tier-1:

- **C=8** (93,676 constraints): ~64 s end-to-end — the fast demonstrator.
- **C=128** (1,493,956 constraints, the full pipeline chunk): witness
  extension **884 s** + collaborative Groth16 **14 s** ≈ **15 min**,
  verified. The proving step is cheap (constant-size communication,
  per-party CPU ≈ one rapidsnark prover); MPC witness extension of the
  Poseidon/EC gadgets is the pole. For N=10^3 (16 chunks) the chunks are
  independent, so with one 3-party worker-set per chunk they run
  concurrently (~15 min wall) up to ~4 h fully sequential.

Latency note: on loopback the round-trip is ~0.05 ms; the benchmarked
regime assumes **1 ms** inter-server latency (co-located authorities).
Because MPC witness extension of the Poseidon/EC gadgets is round-heavy,
real 1 ms links are SLOWER than loopback — localhost timings are a lower
bound for a 1 ms deployment, not an upper bound.
