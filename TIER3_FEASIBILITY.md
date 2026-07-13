# Full Tier-3 for N≈10³: monolithic feasibility, and the chunked-MPC design

This document (1) assesses whether a NO-CHUNK monolithic full-MPC tally
circuit for up to 1000 voters / ~2048 ballot slots is feasible on this
stack, and (2) — because it is not — specifies the chunked full-Tier-3
architecture in which all cross-chunk state stays secret-shared.

## 1. Monolithic 2048-slot feasibility — measured

The full monolithic MPC relation (validity + record generation + Batcher
sort + duplicate handling + tally output), widened to depth-11 registration
and an idBits/posBits sort key (`components/filter_and_tally_mpc_large.circom`),
was compiled at two sizes:

| board B | depth | constraints | per-ballot |
|---|---|---|---|
| 512 (`mid512_mpc`) | 11 | **5,688,324** (measured) | ~11,110 |
| 2048 (`large_mpc`) | 11 | **~24 M** (projected; did NOT compile — see below) | ~11,700 |

Validity is linear in B (~10.9k/ballot at depth 11: signature ~3.6k,
Poseidon hashing, Merkle depth-11, strict decompositions); the Batcher sort
is O(B·log²B) (≈2.1 M constraints at B=2048). So B=2048 ≈ **24 M
constraints**.

**The 2048 circuit does not even COMPILE on this machine.** `circom` on
`filter_and_tally_large_mpc.circom` (B=2048) got through template
instantiation and was then killed after ~9 min with a **peak memory
footprint of ~75 GB** (this machine has 36 GB) — so the exact 2048
constraint count could not be obtained here, and infeasibility bites at the
COMPILE step, before the ceremony and co-circom blockers below even apply.
(The B=512 circuit, ~5.7 M constraints, compiled fine at ~14 GB peak.)

### The two hard blockers

**(a) Trusted setup exceeds machine RAM.** Groth16/snarkjs needs a
powers-of-tau with domain ≥ constraints:

| B | constraints | ptau power | `powersOfTau28_hez_final_N.ptau` size | groth16 setup peak RAM |
|---|---|---|---|---|
| 128 (medium) | 1.24 M | 2²¹ (have) | 2.4 GB | ~9 GB (fits) |
| 512 | 5.69 M | 2²³ | ~9 GB | ~15–20 GB (tight) |
| 1536 | ~18 M | 2²⁴ | ~18 GB | ~30–36 GB (likely OOM) |
| **2048** | **~24 M** | **2²⁵** | **~36 GB** | **> 36 GB — OOM** |

This machine has **36 GB RAM** and locally only pot21 (2²¹). A 2048-slot
circuit needs pot25: the ptau file alone (~36 GB) does not fit in RAM for
`snarkjs groth16 setup`, and the resulting `.zkey` would be ~20 GB. The
setup **cannot be produced here** — which is precisely why the chunked
pipeline exists (each chunk circuit is ≤2²¹, so its ceremony is the
already-available pot21).

**(b) co-circom cannot MPC-extend the sort/duplicate/tally stage.**
Independently of size, co-circom v0.10.0's MPC witness extension
miscompiles the duplicate/tally circuitry (unsatisfying witness under its
optimiser; VM panic/hang otherwise; both Strategy A and B; at nb = 4/16/128,
verified last round). The phase-1 validity relation — same gadgets minus
that stage — extends and proves in MPC fine. So even with an adequate
ceremony, a full-relation MPC witness extension would not run; only the
`proving-mpc` path (central witness) works, which by definition
materializes the full witness centrally and thus fails the requirement.

### Projected co-circom cost (had it been runnable)

From the measured validity chunk (1.49 M constraints → 884 s MPC witness
extension + 14 s collaborative proving): a 24 M-constraint monolithic
witness extension would be ~16× ≈ **~4 hours** (if it worked), proving
~seconds. This confirms the monolithic route is impractical here even
setting the two blockers aside.

### Verdict: INFEASIBLE on this stack (no-chunk, 2048)

Blocked THREE times over, in order of when they bite:
0. the circuit does not compile (circom ~75 GB peak footprint > 36 GB RAM);
1. even if compiled, the 2²⁵ ceremony (~36 GB ptau) exceeds 36 GB RAM so
   the zkey cannot be produced;
2. even with a zkey, co-circom cannot MPC-extend the sort/duplicate stage
   at any size.
We therefore pivot to a chunked architecture whose cross-chunk state stays
secret-shared (each chunk circuit is small enough to compile, set up under
pot21, and — for validity — MPC-prove today).

## 2. Chunked full Tier-3 — architecture (all cross-chunk state secret-shared)

Goal: prove the whole relation for B = KC ballots with each circuit ≤ 2²¹
(so pot21 suffices), and with NO central orchestrator ever seeing openings,
records, sorted records, duplicate structure, or partial tallies — only the
final public tally.

### Stages and what stays secret-shared

1. **Per-chunk validity (works today).** For each chunk k, co-circom MPC
   witness extension computes the C records `r_j=(valid,id,pos,m)` as REP3
   shares and outputs the hiding commitment `rc_k` (public). Openings and
   R_EA enter as provider shares (per-voter, §3). — *This is `vchunkmpc`,
   already MPC-proven and measured.*

2. **Export record shares (NEW primitive needed).** The records must leave
   phase 1 as REP3 shares to feed the sort — NOT as a plaintext any party
   holds. co-circom's `generate-witness` writes the whole witness as shares;
   the records are specific signals in it. Required: a small tool over
   `mpc-core` that extracts the record signals' shares from each party's
   witness-share file (or a co-circom feature to emit designated output
   signals as reusable input shares). *Not provided by co-circom today.*

3. **Oblivious global sort/merge (NEW MPC component).** Sort the K·C record
   shares by (-valid, id, pos) with an MPC sorting/merging network:
   compare-exchange = an MPC comparison (bit-decomposition of the packed
   key on shares) + an oblivious swap (multiplex on shares). Output: the
   sorted records as REP3 shares. No party learns the order or any record.
   Implementable directly on `mpc-core` REP3 arithmetic (a Batcher network
   of MPC compare-exchanges), or via an oblivious-shuffle-then-sort. This is
   the load-bearing new build; it is standard MPC but nontrivial (~K·C·log²
   comparisons, each a multi-round MPC comparison). *Not provided by
   co-circom; would reuse its `mpc-core`.*

4. **Per-run sorted proof (likely works in co-circom).** The existing
   `sorted_run_chunk` circuit does NOT sort — it takes sorted records as
   input and proves in-run + cross-run sortedness (LessEqThan), first-valid
   counting (IsEqual), a hiding partial-tally commitment, and a
   grand-product permutation term. These are the gadgets co-circom already
   handles in the validity chunk (no GreaterThan compare-exchange sort). So
   feeding the SORTED record shares (from stage 3) into an MPC witness
   extension of `srun` is expected to work — to be confirmed. The
   grand-product across chunks binds the sorted sequence as a permutation of
   the originals without revealing either.

5. **Tally-sum (simple, expected to work).** `tally_sum_chunk` opens the K
   hiding partial-tally commitments and outputs their sum — only the final
   tally is revealed. Field adds + Poseidon; co-circom-friendly.

6. **Public output:** the final tally + the public election statement
   (bb_commitment, mr, candidate-set commitment, num_ballots, num_voters,
   duplicate_rule_id, pk_ea_commitment). Everything else stays committed.

### The critical-path dependencies (what must be built/fixed)

- **Inter-circuit secret-share transport** (stage 2): extract designated
  witness-signal shares from one co-circom circuit and inject them as input
  shares to the next. Needs an `mpc-core` tool or a co-circom feature.
- **MPC oblivious sort on REP3 shares** (stage 3): the one genuinely new
  cryptographic component. Buildable on `mpc-core`; the main effort.
- **Confirm co-circom witext of `srun`/`tsum`** (stages 4–5): plausibly
  works (no sort network), but unverified; if the same MPC-VM bug bites the
  LessEqThan/product chains, those circuits need the same treatment as the
  sort (move to `mpc-core`).

### What is already real vs what remains

- **Real / measured:** per-chunk validity fully in MPC (records secret-
  shared inside, rc revealed); the collaborative-proving path for the whole
  relation (central witness — a partial result); per-voter decentralized
  input sharing (§3).
- **Remaining for chunked full Tier-3:** stages 2 and 3 (share transport +
  MPC oblivious sort) are the substantial new build; stages 4–5 need a
  co-circom witext confirmation. None is a quick change — the oblivious sort
  on `mpc-core` is a research-grade component.

## 3. Decentralized input sharing (no single opening-provider bottleneck)

The tally-circuit openings are array-valued (`pt[nb]`, `rho[nb]`, `ct[nb]`,
registration rows, paths): every ballot is an entry of the SAME named
input. co-circom's `merge-input-shares` combines inputs BY NAME (disjoint
names across providers), so it cannot have N voters each own one array
ENTRY of `pt` — a subtlety confirmed when partitioning R_EA into two
separately-named share arrays earlier.

The correct decentralized design is therefore share-PLACEMENT, not merge:

1. Each voter i secret-shares only its own ballot entry
   (pt_i, rho_i, ct_i, and its registration row/path) into REP3 shares and
   sends party p its p-th share — no voter sees another's opening.
2. Each party p assembles its share-arrays locally by placing voter i's
   p-th share at index i (a purely local operation on shares — no plaintext
   is ever reconstructed).
3. The authority-share arrays (`r_ea_share_a/b`) are contributed the same
   way, per authority.

No process ever materializes all openings or the full plaintext input; each
party holds only an array of shares. This removes the single
opening-provider bottleneck. **Status: designed.** A prototype needs the
same `mpc-core` share-format handling as stage 2 (§2) to write co-circom
`.shared` array files from per-voter shared entries; it is not expressible
with `split-input`/`merge-input-shares` alone. The current
`tier3::full_providers` builds the provider files from one process (the
benchmark harness, which generated the synthetic election and so holds all
secrets by construction) — adequate for benchmarking the MPC, but the
per-voter share-placement above is what a real deployment uses.

## Summary

A no-chunk monolithic full-MPC tally for 2048 slots is **infeasible on this
stack**: the circuit does not even compile here (circom ~75 GB peak footprint
vs 36 GB RAM); ~24 M constraints would need a 2²⁵ ceremony that also exceeds
36 GB RAM; and co-circom cannot MPC-extend the sort/duplicate stage at any
size. The
feasible route to full Tier-3 is the **chunked** architecture above, whose
only fundamentally new component is an **MPC oblivious sort over
secret-shared records** (plus inter-circuit share transport); the rest maps
onto co-circom circuits that are already MPC-proven (validity) or expected
to be MPC-friendly (sorted-run/tally-sum). That oblivious sort is the honest
remaining research build.
