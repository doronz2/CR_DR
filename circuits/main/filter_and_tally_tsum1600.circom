pragma circom 2.0.0;

// Chunked pipeline, final stage: TallySum over K = 1600 runs, 3 candidates.

include "./tally_sum_chunk.circom";

component main {
    public [tc, acc_p_cm, acc_q_cm, tally_counts]
} = TallySum(1600, 3);
