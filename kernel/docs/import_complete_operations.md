# Complete-operation observations

`tools/import_complete_operations.py` converts a completed acquisition from
`bench/complete_operations/collect.py` to the existing
`lattice.block_observation_shards.v2` schema. It verifies the prepared driver,
source snapshots, binary hashes, randomized schedule, command journal, process
returns, CSV values and matching input/output sequences before creating the
public observations manifest. It runs no benchmark or cryptographic operation.

Supply the original configuration and an explicit JSON mapping containing every
acquisition label exactly once. Mapping values are distinct technical identifiers
such as `shared-kernel`, `native-reference` and `portable-reference`. All recorded
configurations are retained. The mapping changes identifiers, not samples.

```text
python tools/import_complete_operations.py --input ACQUISITION --configuration CONFIG.xml --labels LABELS.xml --dataset-id STUDY --platform windows_x86_64 --output OBSERVATIONS --audit LOCAL_AUDIT.xml
```

Use `linux_aarch64` for a matching Linux/AArch64 acquisition. The source binary
and prepared-driver paths must still be accessible for verification. Keep the
local audit outside the public observations directory. The audit retains source
paths, label mapping and per-file provenance; the public directory contains
relative shard paths and cryptographic identities. Original CSV files are copied
byte for byte, including warmups and slow observations. Compiler flag text stays
in the original hash-bound log. Public metadata uses the closed schema.

The importer requires a complete successful acquisition. Failed runs,
checkpoints, altered artifacts and unmatched pairs produce an error while their
original records remain intact. Partial conversion files remain in a separate
`.incomplete-...` directory; the final output path appears after validation.

Derive and replay statistics with the existing public tools:

```text
python analysis/pooled_statistics.py derive --observations OBSERVATIONS/observations.xml --comparisons COMPARISONS.xml --output OBSERVATIONS/summary.xml --resamples 10000 --seed 2026100313511
python analysis/pooled_statistics.py recompute --observations OBSERVATIONS/observations.xml --summary OBSERVATIONS/summary.xml
python analysis/pooled_view.py --observations OBSERVATIONS/observations.xml --summary OBSERVATIONS/summary.xml --output TABLES
```

Each comparison has `id`, `reference` and `candidate` fields. The pooled summary
uses **reference-over-candidate median ratios** and complete-block resampling.
Its operation table separately includes means, medians, P95 and P99. Mean-ratio
inference requires a separately named statistical model.

The finite importer regression accepts the same completed archive and creates
altered copies in a fresh test directory. It checks explicit rejection reasons
for 18 fixed malformed cases, then executes the documented CLI from its own
tools directory and verifies every original observation. The supplied archive
is read-only.

```text
python tests/test_import_complete_operations.py --study ACQUISITION --configuration CONFIG.xml --labels LABELS.xml --output TEST_RESULTS
```
