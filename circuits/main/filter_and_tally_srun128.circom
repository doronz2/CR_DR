pragma circom 2.0.0;

// Chunked pipeline, phase 2: SortedRunChunk with C = 128 records,
// 3 candidates.

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
        pp,
        qq
    ]
} = SortedRunChunk(128, 3);
