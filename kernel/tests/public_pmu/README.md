# Exact PMU leaf data

`publicschemas/pmu_v1.py` defines a closed, path-free scientific manifest and summary. The `validate_manifest` and `validate_summary` routines check structure; the consumer below validates raw files.

Recompute all integer counts and fractions from the supplied public CSV files:

```powershell
python -B tools/recompute_pmu.py --manifest D:/pqc-data/pmu/observations.xml --output D:/pqc-data/pmu/recomputed.xml
python -B -m unittest discover -s tests/public_pmu -v
```

The consumer verifies every CSV SHA-256, byte count, row count and exact integer sum. Each configuration contains all six parameters and three operations. No leaf is removed, including outside modules and unresolved symbols. Unknown addresses are represented by separate stable leaf identifiers; reported user/kernel symbol context is retained. No raw host address, DWARF stack or machine path is part of the public data.

`samples` counts retained samples. `period` sums sampled event periods; it is not a sample count, an exact hardware total, an operation latency, or a cycle counter measured around one call. Both all-process and target-module-conditional fractions are computed from these integers with distinct denominators. Lost-sample counts remain visible. Rounded percentages printed by perf are not inputs to recomputation.

These profiles use fixed serialized key/message inputs and fresh operation entropy. Process setup and external code remain in the all-process population. Independent-input latency and its confidence interval are measured separately.

The private export uses documented Linux perf leaf reporting (`--no-children`, no call graph, zero percentage cutoff, `sample,period,dso,symbol` fields); see the [Linux 5.15 perf-report manual](https://github.com/torvalds/linux/blob/v5.15/tools/perf/Documentation/perf-report.txt). The public test fixtures are synthetic only.
