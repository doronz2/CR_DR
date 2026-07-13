# Tier-3 (decentralized / coSNARK) — implementation status

Consolidated status of what is implemented, what is measured, and what is
blocked. Full detail in TIER3_DESIGN.md (architecture + real-vs-simulated
matrix) and TIER3_FEASIBILITY.md (monolithic-2048 assessment + chunked
design). All code is on `origin/main` (through commit `33c0f6d`).

## TL;DR

- **Fully decentralized in MPC, including witness extension — DONE, measured:**
  the tally-VALIDITY relation (`prove_tier3`). No party ever holds the
  witness, R_EA, openings, validity flags, or identities.
- **Full relation (validity+sort+duplicate+tally) — implemented + proven
  correct; MPC proving works, MPC witness extension blocked upstream:**
  `prove_tier3_full`. `--mode proving-mpc` completes and verifies (central
  witness); `--mode full-mpc` is blocked by a co-circom v0.10.0 bug.
- **No-chunk monolithic 2048 (N≈10³) — INFEASIBLE on this machine** (doesn't
  compile; ceremony > RAM; co-circom bug). Pivot = chunked full Tier-3 whose
  one new component is an MPC oblivious sort (not yet built).

## What is implemented

### Circuits
- `components/lagrange_combine.circom` — in-circuit Shamir reconstruction of
  R_EA from t=2 shares (`2·s₁−s₂`); linear, zero added constraints.
- `main/validity_chunk_mpc.circom` + `filter_and_tally_vchunkmpc{128,8}` —
  Tier-3 validity chunk: R_EA from separate per-authority share inputs,
  public inputs byte-identical to Tier-1 `vchunk128`. 1,493,956 constraints
  (== Tier-1; combine is free).
- `components/{duplicate_sorted_out,tally_accumulator_out}.circom` — tally as
  a public OUTPUT (revealed by the MPC), not a checked input.
- `components/filter_and_tally_mpc.circom` + `main/{small,medium}_mpc(_naive)`
  — full monolithic relation, `dupStrategy` param (B=sorted / A=naive),
  R_EA in-circuit, tally output. medium_mpc = 1,235,915 constraints.
- `components/sort_records_wide.circom` + `filter_and_tally_mpc_large.circom`
  + `main/{mid512,large}_mpc` — width-parameterized (idBits/posBits, depth)
  for large boards; mid512 (B=512, depth 11) = 5,688,324 constraints
  (measured); large (B=2048) does not compile here (see feasibility).

### Rust (`src/zk/tier3.rs`, bins `prove_tier3`, `prove_tier3_full`)
- `chunk_providers` / `full_providers` — provider-partitioned circuit inputs
  (opening / authority_a / authority_b); R_EA appears in NO provider file;
  the full witness is not assembled before co-circom split/merge. Built
  without `build_chunked_tally`.
- `CoCircomBackend` — drives the `co-circom` binary through split-input →
  merge-input-shares → generate-witness (MPC) → generate-proof (MPC) →
  verify, reusing the snarkjs `.zkey`; `prove_chunk` (full MPC) and
  `prove_collaborative` (split-witness + MPC proving); TLS/party config gen.
- `prove_tier3` — validity relation, full MPC.
- `prove_tier3_full` — full relation; `--mode full-mpc` | `proving-mpc`;
  public-input binding of the revealed tally + statement.

### Tests (`tests/tier3_tests.rs`)
- Always-on (native): provider partition hides R_EA/tally/records;
  in-circuit combine == Shamir reconstruction.
- Opt-in (`CR_DR_TIER3_MPC=1`): real 3-party MPC validity proof verifies;
  full-relation collaborative proof verifies with correct tally.

### Docs
TIER3_DESIGN.md, TIER3_FEASIBILITY.md, README "Prover tiers" (Tier 3),
BENCHMARKS.md "Tier-3" section.

## What is measured (Apple M3 Max, 3 localhost REP3 parties)

| what | result |
|---|---|
| validity chunk C=8 (`vchunkmpc8`, 93,676 c) full MPC | ~64 s, verified |
| validity chunk C=128 (`vchunkmpc128`, 1,493,956 c) full MPC | 884 s witext + 14 s prove, verified |
| full relation nb=128 (`medium_mpc_naive`) `--mode proving-mpc` | 19.3 s, verified, revealed tally correct |
| monolithic B=512 compile | 5,688,324 constraints, ~14 GB peak (OK) |
| monolithic B=2048 compile | killed, circom ~75 GB peak > 36 GB RAM |

Headline finding: co-circom collaborative PROVING is cheap (constant-size
comms; 14 s at 1.49 M constraints); MPC WITNESS EXTENSION of the Poseidon/EC
gadgets dominates (884 s). Localhost 3-party = cryptographically real but
architecturally simulated trust domains.

## What is blocked / not done

1. **co-circom v0.10.0 MPC witness extension miscompiles the sort/duplicate/
   tally stage** — wrong witness under its optimiser, panic/hang otherwise;
   both duplicate strategies; nb=4/16/128. So the FULL relation's witness
   extension cannot run in MPC (validity works). The circuit is proven
   correct independently (snarkjs; co-circom collaborative proving on a
   split witness). ⇒ full relation is only `proving-mpc` (central witness).
2. **No-chunk monolithic 2048** infeasible here: compile OOM (~75 GB), 2²⁵
   ceremony (~36 GB ptau) > 36 GB RAM, plus (1).
3. **Chunked full Tier-3** (the feasible route) needs two new components,
   NOT yet built: (a) inter-circuit secret-share transport (export phase-1
   record shares), (b) an **MPC oblivious global sort** over secret-shared
   records on `mpc-core` — the load-bearing research build. Stages 4–5
   (`srun`/`tsum` in MPC) are expected to work but unconfirmed.
4. **Decentralized per-voter input sharing** designed (share-placement, not
   name-based merge) but not prototyped; current provider files are built by
   the benchmark harness (which holds all secrets by construction).

## Suggested next step

Confirm co-circom can MPC-witness-extend the `srun`/`tsum` circuits (cheap;
validates chunked stages 4–5), THEN build the `mpc-core` oblivious sort —
the single component that unlocks a ceremony-feasible full Tier-3.
