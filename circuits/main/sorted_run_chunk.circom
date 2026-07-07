pragma circom 2.0.0;

// Phase-2 chunk of the CHUNKED FilterAndTally pipeline (see
// CHUNKED_TALLY_DESIGN.md): one run of C records of the GLOBALLY sorted
// record sequence, plus the chunk's original records re-opened.
//
// Together with the aggregator's public checks this realizes, across
// chunks, exactly what the monolithic sorting network realizes inside one
// circuit:
//   * permutation: grand products P (sorted side) and Q (original side)
//     under challenge (gamma, delta) derived AFTER both rc (original
//     order, from validity chunks) and sc (sorted runs, this circuit's
//     re-opened commitment) are fixed — the aggregator checks
//     prod_k P_k == prod_k Q_k;
//   * sortedness: in-run adjacent key comparisons plus a hiding
//     boundary-record commitment chain across runs;
//   * first-valid counting on adjacent sorted records (the boundary
//     record supplies the cross-run predecessor);
//   * partial tallies leave the chunk ONLY as a hiding commitment tc
//     (opened jointly by tally_sum_chunk.circom, revealing only totals).
//
// Sort key (ascending) = (1-valid)*2^24 + id*2^16 + pos, faithful because
// valid is boolean, id < 2^9 (sentinel 256; real ids < 2^8) and
// pos < 2^16 — all range-checked here, so comparators are sound
// independently of the permutation argument.
//
// Public products pp/qq are both blinded by the same nonzero rho_blind,
// so prod pp == prod qq iff prod P == prod Q while individual products
// reveal nothing.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "../components/record_chain.circom";

template SortedRunChunk(C, nC) {
    // ---------------- public inputs ----------------
    signal input gamma;             // multiset challenge (Fiat-Shamir)
    signal input delta;             // record-encoding challenge
    signal input rc;                // this chunk's original-record commitment
    signal input sc;                // this run's sorted-record commitment
    signal input boundary_in_cm;    // hiding commitment to predecessor record
    signal input boundary_out_cm;   // hiding commitment to this run's last record
    signal input tc;                // hiding commitment to the partial tally
    signal input pp;                // rho_blind * prod (gamma - enc(sorted_i))
    signal input qq;                // rho_blind * prod (gamma - enc(orig_j))

    // ---------------- private witness ----------------
    signal input orig[C][4];        // chunk k's records, board order
    signal input rc_blind;
    signal input sorted[C][4];      // run k of the globally sorted sequence
    signal input sc_blind;
    signal input bnd_in[4];         // predecessor record (sentinel for run 0)
    signal input bnd_in_blind;
    signal input bnd_out_blind;
    signal input tally_blind;
    signal input rho_blind;
    signal input rho_inv;           // forces rho_blind != 0

    rho_blind * rho_inv === 1;

    // -------- re-open both phase-1 commitments (binding to pre-challenge data)
    component rchain = RecordChain(C);
    rchain.blind <== rc_blind;
    component schain = RecordChain(C);
    schain.blind <== sc_blind;
    for (var j = 0; j < C; j++) {
        for (var f = 0; f < 4; f++) {
            rchain.records[j][f] <== orig[j][f];
            schain.records[j][f] <== sorted[j][f];
        }
    }
    rchain.out === rc;
    schain.out === sc;

    // -------- boundary commitments
    component bin = RecordCommit();
    component bout = RecordCommit();
    for (var f = 0; f < 4; f++) {
        bin.record[f] <== bnd_in[f];
        bout.record[f] <== sorted[C - 1][f];
    }
    bin.blind <== bnd_in_blind;
    bout.blind <== bnd_out_blind;
    bin.out === boundary_in_cm;
    bout.out === boundary_out_cm;

    // -------- range checks making the packed key faithful
    component validBit[C + 1];
    component idBits[C + 1];
    component posBits[C + 1];
    signal rawKey[C + 1];  // rawKey[0] = boundary_in, rawKey[j+1] = sorted[j]
    for (var j = 0; j <= C; j++) {
        var v[4];
        if (j == 0) {
            for (var f = 0; f < 4; f++) { v[f] = bnd_in[f]; }
        } else {
            for (var f = 0; f < 4; f++) { v[f] = sorted[j - 1][f]; }
        }
        validBit[j] = Num2Bits(1);
        validBit[j].in <== v[0];
        idBits[j] = Num2Bits(9);       // sentinel id = 256 needs 9 bits
        idBits[j].in <== v[1];
        posBits[j] = Num2Bits(16);
        posBits[j].in <== v[2];
        rawKey[j] <== (1 - v[0]) * 16777216 + v[1] * 65536 + v[2];
    }

    // The run-0 sentinel predecessor (id = 256) must not constrain
    // sortedness: its key is zeroed (0 <= anything). Sound because no
    // multiset-bound record can carry id 256 (real record ids are < 2^8),
    // and non-sentinel boundary records are multiset-bound via the
    // previous run's boundary_out commitment.
    component isSent = IsEqual();
    isSent.in[0] <== bnd_in[1];
    isSent.in[1] <== 256;
    signal key[C + 1];
    key[0] <== (1 - isSent.out) * rawKey[0];
    for (var j = 1; j <= C; j++) {
        key[j] <== rawKey[j];
    }

    // -------- sortedness: key[j] <= key[j+1] (boundary included)
    component le[C];
    for (var j = 0; j < C; j++) {
        le[j] = LessEqThan(25);
        le[j].in[0] <== key[j];
        le[j].in[1] <== key[j + 1];
        le[j].out === 1;
    }

    // -------- first-valid counting on adjacent sorted records
    component sameId[C];
    signal counted[C];
    for (var j = 0; j < C; j++) {
        var prevId = 0;
        if (j == 0) {
            prevId = bnd_in[1];
        } else {
            prevId = sorted[j - 1][1];
        }
        sameId[j] = IsEqual();
        sameId[j].in[0] <== sorted[j][1];
        sameId[j].in[1] <== prevId;
        counted[j] <== sorted[j][0] * (1 - sameId[j].out);
    }

    // -------- partial tally, committed (hiding)
    component mEq[C][nC];
    signal contrib[C][nC];
    component tcm = Poseidon(nC + 1);
    for (var c = 0; c < nC; c++) {
        var sum = 0;
        for (var j = 0; j < C; j++) {
            mEq[j][c] = IsEqual();
            mEq[j][c].in[0] <== sorted[j][3];
            mEq[j][c].in[1] <== c;
            contrib[j][c] <== counted[j] * mEq[j][c].out;
            sum += contrib[j][c];
        }
        tcm.inputs[c] <== sum;
    }
    tcm.inputs[nC] <== tally_blind;
    tcm.out === tc;

    // -------- grand products under (gamma, delta), blinded by rho_blind
    // enc(r) = valid + delta*id + delta^2*pos + delta^3*m
    signal d2;
    signal d3;
    d2 <== delta * delta;
    d3 <== d2 * delta;
    signal sId[C];
    signal sPos[C];
    signal sM[C];
    signal oId[C];
    signal oPos[C];
    signal oM[C];
    signal encS[C];
    signal encO[C];
    signal accP[C + 1];
    signal accQ[C + 1];
    accP[0] <== rho_blind;
    accQ[0] <== rho_blind;
    for (var j = 0; j < C; j++) {
        sId[j] <== delta * sorted[j][1];
        sPos[j] <== d2 * sorted[j][2];
        sM[j] <== d3 * sorted[j][3];
        encS[j] <== sorted[j][0] + sId[j] + sPos[j] + sM[j];
        oId[j] <== delta * orig[j][1];
        oPos[j] <== d2 * orig[j][2];
        oM[j] <== d3 * orig[j][3];
        encO[j] <== orig[j][0] + oId[j] + oPos[j] + oM[j];
        accP[j + 1] <== accP[j] * (gamma - encS[j]);
        accQ[j + 1] <== accQ[j] * (gamma - encO[j]);
    }
    accP[C] === pp;
    accQ[C] === qq;
}
