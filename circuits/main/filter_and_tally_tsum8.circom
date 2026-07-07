pragma circom 2.0.0;

// Chunked pipeline, final stage: TallySum over K = 8 runs, 3 candidates.

include "./tally_sum_chunk.circom";

component main {
    public [tc, tally_counts]
} = TallySum(8, 3);
