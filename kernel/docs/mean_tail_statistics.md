# Mean and tail inference

`analysis/mean_tail_statistics.py` derives and exactly replays statistics from
the public observation manifest and its original CSV shards. It also accepts
the existing inline observation schema for small tests. All configurations,
eighteen operations, blocks and recorded samples remain in the input.

```text
python analysis/mean_tail_statistics.py derive --observations OBSERVATIONS/observations.xml --comparisons COMPARISONS.xml --output MEAN_TAIL.xml --resamples 10000 --seed 2026100313511
python analysis/mean_tail_statistics.py recompute --observations OBSERVATIONS/observations.xml --summary MEAN_TAIL.xml
```

Each comparison contains `id`, `reference` and `candidate`. Every ratio in this
schema is **candidate time divided by reference time**. A ratio below one
indicates a shorter candidate time. The separate pooled-median schema uses its
own explicitly named ratio direction.

The output schema is `lattice.mean_tail_statistics.v1`. Each operation contains
the mean, median, P95 and P99 in nanoseconds and a 95% percentile interval. Each
comparison contains their ratios and intervals, plus the geometric mean of the
eighteen mean-time ratios and its interval. All point intervals describe their
named statistic; the mean and percentile estimators stay distinct.

One PCG64 draw selects complete blocks with replacement. The same block indices
apply to every configuration, operation and statistic. Means are calculated
from the equal-sized blocks. Quantiles use the pooled calls in the selected
blocks, with linear type-7 interpolation. Integer block multiplicities preserve
the exact repeated-block quantile. Warmups remain in the observations and are
excluded from statistical estimates. Slow measured calls remain included.

The schema binds the observation bytes, ordered runs, all configuration binary
hashes and workspaces, eleven analysis/schema source files, and bootstrap draw
and replicate digests. Recompute validates these identities before repeating
the calculation. Incomplete acquisitions, failed records, changed shard hashes,
unpaired transcripts and nonpositive timing values cause an error.

The finite regression uses synthetic data only. It compares 10,512 statistic
replicates with explicitly concatenated sampled blocks and checks paired
correlation, ratio direction, extreme-call retention and explicit error cases.

```text
python tests/test_mean_tail_statistics.py --output TEST_RESULT.xml
```
