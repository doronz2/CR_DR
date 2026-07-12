pragma circom 2.0.0;

// Chunked pipeline, phase 2: SortedRunChunk with C = 128 records,
// 3 candidates, 14-bit identities (sentinel 2^14).

include "./sorted_run_chunk.circom";

component main {
    public [
        gamma,
        delta,
        rc,
        sc,
        boundary_in_cm,
        boundary_out_cm,
        tc,
        acc_p_in_cm,
        acc_p_out_cm,
        acc_q_in_cm,
        acc_q_out_cm
    ]
} = SortedRunChunk(128, 3, 14);
