pragma circom 2.0.0;

// Chunked pipeline, final stage: TallySum over K = 4 runs, 3 candidates.

include "./tally_sum_chunk.circom";

component main {
    public [tc, tally_counts]
} = TallySum(4, 3);
