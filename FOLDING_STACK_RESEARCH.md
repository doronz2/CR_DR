# Research note: folding/composition stack for CR-DR at scale (July 2026)

Deep-research sweep (multi-source, adversarially verified claims) to pick a
proving stack for the BN254-native tally relation (~8k R1CS constraints per
ballot slot, boards to 2M slots), preserving Poseidon-BN254 + BabyJubJub
with a small final proof. Companion to CHUNKED_TALLY_DESIGN.md and
BENCHMARKS.md. Confidence labels reflect 3-vote verification of each claim
against primary sources.

## Verified findings

**Sonobe (PSE / privacy-ethereum)** — HIGH confidence
* Implements Nova, CycleFold, HyperNova, ProtoGalaxy (partial) in one
  library — the broadest folding coverage anywhere; microsoft/Nova has
  Nova/HyperNova, Barretenberg has ProtoGalaxy only.
* `DeciderEth`: final compression to a single **Groth16-over-BN254** proof
  (+ KZG10 evaluation proofs) with generated Solidity verifier. CAVEAT:
  the EVM decider currently supports only the **Nova+CycleFold** path, not
  the HyperNova/ProtoGalaxy frontends; decider adds O(n log n) NTT cost.
* Maturity: "experimental, do not use in production", no official release;
  a Nova/CycleFold staging audit was conducted ~June 2026 (per PSE blog),
  first release planned; Intmax zERC20 reports production use.
  [github.com/privacy-ethereum/sonobe, sonobe.pse.dev]

**microsoft/Nova + MicroNova** — HIGH confidence
* Native **BN254/Grumpkin** cycle support; constant per-step recursion
  overhead ≈ **10k multiplication gates**; deciders are Spartan-based
  (MicroSpartan, from the MicroNova paper, IEEE S&P 2025) — no Groth16
  wrap in-repo. Circom circuits need an adapter (Nova-Scotia-style);
  crate nova-snark 0.71.0; unaudited.
* MicroNova: on-chain verification ≈ **2.2M gas** (~8–10× a bare Groth16
  verify), roughly constant up to ~2^21 folding steps; **universal setup
  reusing existing KZG powers-of-tau** — no circuit-specific ceremony.
  [github.com/microsoft/Nova, eprint 2024/2099]

**Mova (eprint 2024/1220)** — HIGH confidence, NEGATIVE for us
* Its 5–10× prover speedup over Nova assumes SMALL witness elements.
  Poseidon-BN254 states and BabyJubJub coordinates are uniform full-field
  scalars, so the assumption fails for this relation; even in the
  favorable regime Mova is only ~1.05–1.3× over HyperNova. Skip.

**Memory profile of folding** — MEDIUM confidence (dated benchmark,
structural property corroborated)
* PSE nova-bench (72-core / 350GB server, recursive SHA-256, 2023): Nova
  prover memory ~**1.6 GB constant** from 100 → 10,000 steps, vs
  monolithic Halo2-KZG 3.7 GB → 32 GB → **245 GB**. Run on Pasta curves,
  not BN254/Grumpkin; not apples-to-apples; the constant-memory property
  itself is structural and corroborated by MicroNova.

**Small-field STARKs do not transfer to this relation** — MEDIUM/HIGH
* Stwo (Circle STARKs / M31): 500k–620k Poseidon2 hashes/s on laptop-class
  CPUs — but for **M31-native Poseidon2**, not Poseidon-BN254.
* The emulation tax is quantified by SP1's own precompile numbers: ONE
  BN254 pairing ≈ 6.6M zkVM cycles (after a 23.5× precompile speedup);
  a Groth16 verification inside the zkVM ≈ 9.4M cycles. Wide-field
  crypto inside small-field zkVMs remains expensive; preserving
  Poseidon-BN254/BabyJubJub rules this path out short of a protocol
  redesign.

**SnarkPack (FC 2022)** — HIGH confidence
* Aggregates **8192 Groth16 proofs in 8.7 s**, aggregate verify 33–163 ms
  (32-core Threadripper, BLS12-381 — upper bound for BN254). **No new
  trusted setup**: reuses two independent existing powers-of-tau
  transcripts (Perpetual Powers of Tau qualifies for BN254; Aztec
  Ignition, being G1-only, may not). Proof is **O(log n)**, not constant
  (SnarkFold, eprint 2023/1946, targets that gap).
* Fit: pairs directly with CHUNKED_TALLY_DESIGN.md — 16,384 chunk proofs
  would aggregate in ~17 s with sub-second verification.

**Gaps**: no benchmark claims for LatticeFold+, hash-based accumulation
(ARC/Khatam/WHIR-based), GKR provers (Expander), or Binius survived
verification — these remain research-stage or lack published numbers for
comparable workloads; Nexus/arecibo throughput likewise unverified.

## Recommendation

1. **Primary: Sonobe Nova+CycleFold with DeciderEth** — BN254/Grumpkin
   keeps Poseidon-BN254/BabyJubJub bit-for-bit; the audit-track code path
   is exactly this configuration; final proof is a single Groth16-over-
   BN254 (+KZG) with a generated Solidity verifier. HyperNova inside
   Sonobe is NOT the pragmatic pick today (no EVM decider, less mature),
   contrary to what per-step asymptotics alone would suggest.
2. **Alternative: microsoft/Nova + MicroNova** — better-studied core,
   S&P-published decider, universal setup, ~2.2M gas on-chain (or cheap
   off-chain) verification; costs a Circom-to-bellpepper adapter and
   forgoes the 0.8 KB Groth16 wrap.
3. **Near-term composition without leaving circom: chunked Groth16 +
   SnarkPack** (see CHUNKED_TALLY_DESIGN.md) — all engineering stays in
   the current stack; accept an O(log n) ~KB-scale aggregate proof.
4. Do not pursue Mova (witness profile mismatch) or small-field STARKs
   (primitive migration = protocol redesign) for this relation.

All three viable paths are experimental-to-young; for a production voting
system, audit status (Sonobe's June-2026 Nova/CycleFold audit is the
furthest along) should weigh as much as throughput.
