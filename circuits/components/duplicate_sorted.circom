pragma circom 2.0.0;

// Strategy B (main): sorted-record first-valid-counts duplicate handling
// and tally accumulation, linear after the sorting network.
//
// From each board slot j the validity stage emits the private record
//     r_j = (valid_j, id_j, pos_j = j, m_j)
// (id_j = valid_j * id: canonical registration index, dummy 0 when invalid;
// m_j = candidate index, dummy 0 when no candidate matches). The records
// are sorted by (-valid, id, pos) — valid first, then id, then board
// position — via the Batcher network (permutation + sortedness by
// construction), then
//     counted_j = valid_sorted_j * is_first_valid_in_identity_block_j,
//     is_first_..._j = 1 iff j = 0 or id_sorted_j != id_sorted_{j-1}
// counts exactly the FIRST valid ballot of each identity (within an id
// block, pos ascends, and all valid records precede all invalid ones, so a
// valid row's predecessor row is valid whenever ids match). Finally
//     tally_counts[c] === sum_j counted_j * [m_sorted_j == c].
//
// Nothing is output: sorted order, records and counted flags stay private.
//
// Validity-before-duplicates is structural here: invalid records carry
// valid = 0 and can never be "first valid" of any identity block, so they
// never consume a voter's slot. (For a future last-valid-counts rule, sort
// with descending pos inside each id block, or test the NEXT row instead
// of the previous one.)

include "circomlib/circuits/comparators.circom";
include "./sort_records.circom";

template DuplicateTallySorted(nB, nC) {
    signal input valid[nB];
    signal input id[nB];            // valid-gated id, < 2^8
    signal input m[nB];             // candidate index, < nC
    signal input tallyCounts[nC];

    component srt = SortRecords(nB);
    for (var j = 0; j < nB; j++) {
        srt.rin[j][0] <== valid[j];
        srt.rin[j][1] <== id[j];
        srt.rin[j][2] <== j;
        srt.rin[j][3] <== m[j];
    }

    component sameId[nB];
    signal counted[nB];
    counted[0] <== srt.rout[0][0];
    for (var j = 1; j < nB; j++) {
        sameId[j] = IsEqual();
        sameId[j].in[0] <== srt.rout[j][1];
        sameId[j].in[1] <== srt.rout[j - 1][1];
        counted[j] <== srt.rout[j][0] * (1 - sameId[j].out);
    }

    component mEq[nB][nC];
    signal contrib[nB][nC];
    for (var c = 0; c < nC; c++) {
        var sum = 0;
        for (var j = 0; j < nB; j++) {
            mEq[j][c] = IsEqual();
            mEq[j][c].in[0] <== srt.rout[j][3];
            mEq[j][c].in[1] <== c;
            contrib[j][c] <== counted[j] * mEq[j][c].out;
            sum += contrib[j][c];
        }
        tallyCounts[c] === sum;
    }
}
