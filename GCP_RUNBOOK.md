# GCP runbook: chunked-tally benchmark at N = 10^4 voters

One command per run once the VM is up. Target: board B = 20,480 ballots
(K = 160 chunks, 321 proofs) — the N = 10^4 row of the composed-cost
table, measured end-to-end instead of extrapolated.

## Machine

**`c3d-highcpu-90`** (90 vCPU AMD Genoa, 177 GB), Spot. Genoa has ADX, so
rapidsnark runs its fast x86-64 assembly path. Memory is generous: each
concurrent prove peaks ~1.1 GB and the zkey pages are mmap-shared.
Anything 60+ vCPU works; `c3-highcpu-88` (Intel SPR) is equivalent.

```bash
gcloud compute instances create crdr-bench \
  --zone=us-central1-a \
  --machine-type=c3d-highcpu-90 \
  --provisioning-model=SPOT --instance-termination-action=DELETE \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=200GB --boot-disk-type=pd-balanced
```

Spot price ≈ $1–1.5/h; a full setup + benchmark session fits in well
under an hour.

## Setup on the VM (~15 min, mostly zkey generation)

```bash
sudo apt-get update && sudo apt-get install -y \
  build-essential cmake m4 nodejs npm git curl libgmp-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

git clone https://github.com/doronz2/CR_DR.git && cd CR_DR
npm install                       # snarkjs + circomlib (repo-local)
cargo install --git https://github.com/iden3/circom --tag v2.1.9 circom
scripts/install_rapidsnark.sh     # native prover (Linux path builds GMP)

# Circuit artifacts. EITHER copy prebuilt zkeys from a bucket:
#   gsutil -m cp gs://<your-bucket>/crdr-artifacts/* build/circuits/
# OR build them here (vchunk zkey ~10 min; ptau downloads in ~1 min):
mkdir -p build/ptau
curl -L -o build/ptau/pot21_final.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau
for v in vchunk128 srun128 tsum160; do
  scripts/compile_circuits.sh $v && scripts/setup_groth16.sh $v
done

cargo test --test chunked_tests   # sanity: 6 tests
```

(To seed a bucket from a machine that already has the artifacts:
`gsutil -m cp build/circuits/filter_and_tally_{vchunk128,srun128,tsum160}*.zkey \
build/circuits/*verification_key.json build/circuits/*_js -r gs://<bucket>/crdr-artifacts/`.)

## Run

```bash
cargo run --release --bin prove_chunked -- --ballots 20480
```

The driver builds the synthetic election (64 registered voters, 5 coerced,
chaff-filled board — board size is the cost driver; see the depth note
below), checks the chunked relation natively, proves all 321 chunk proofs
with `jobs = cores/6` concurrent rapidsnark processes (each internally
multithreaded), then verifies every proof and its public-input binding.
Expected on 90 vCPUs: proving in the low single-digit minutes; the
printed lines are the numbers for the paper's Table (replace the
extrapolated N = 10^4 row).

Options: `--jobs J` to override concurrency, `--ballots`, `--seed`,
`--dry-run` (native pipeline only).

## Notes

* **Registration depth**: the compiled chunk circuits use Merkle depth 6
  (<= 64 voters). A depth-14 tree (10^4 real voters) adds ~250
  constraints per extra level per slot, ~+25% on the validity chunk —
  the honest scaling factor to quote alongside the measured board-size
  numbers.
* **Reproducibility line for the paper**: machine type, repo commit,
  `prove_chunked --ballots 20480 --seed <s>`, and the printed output.
* The trusted setup remains dev-grade (public Hermez ptau + local
  phase 2) — timings are valid, keys are not for production.
