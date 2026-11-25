# Fixed-owner application observations

The `application_owner_views` demo setting accepts explicit `summary` and
`observations` file descriptors, each with a path and SHA-256. This schema describes fixed-pool application observations.

Import a completed acquisition without executing cryptography:

```text
python tools/import_application_owner.py --input ACQUISITION --output NEW_DATASET
```

For a returned archive, repeat `--path-map ORIGINAL_PREFIX=LOCAL_PREFIX` as
needed. Mapping never relaxes the recorded file hashes. `--current-id ID` maps
the input configuration label into the public technical configuration identity;
the core and application hashes remain unchanged. Optional `--audit FILE` keeps
local path mappings outside the public dataset.

The output contains the closed `observations.xml`, independently recomputed
`summary.xml`, numerical `summary.csv`, and byte-identical original process
JSONL and stderr files. It excludes acquisition commands, absolute paths and
private project status. The manifest binds the frozen plan, collector, driver,
compiled application sources, core/application images, CPU index and clock.

Recompute after moving only the public dataset and source tree:

```text
python -m publicschemas.application_owner_v1 DATASET/observations.xml --check DATASET/summary.xml
python tests/test_application_owner_views.py --observations DATASET/observations.xml
```

In a bundle containing the validated Windows CPython 3.13 and NumPy 2.2.5
runtime, the same replay is available through the offline dispatcher:

```text
bin/python/python.exe source/tools/offline_analysis.py --bundle . --entry application-owner -- data/windows-application-owner/observations.xml --check data/windows-application-owner/summary.xml
```

NumPy is needed for the declared PCG64 bootstrap. For N explicitly registered
images (2–10), the 9 complete randomized blocks contain 216N retained batches,
24N timing cells and 12×C(2N,2) paired comparisons. All use one shared set of
50,000 block draws. The manifest declares the seed. Percentile 95% intervals
apply to arithmetic mean **batch** latency; a batch contains 1 or 200 flows.
Throughput divides flow count by mean complete batch time. No individual-flow
P95 or P99 is inferred from batch observations.

The timed boundary includes opening and preparing the application, all flows,
finishing and final close, which clears the entire fixed pool. Loading modules,
physical pool allocation/free, the wide-workspace transcript oracle and post-run
checks are outside. The ordinary timing driver has no heap or stack probe hooks.
Paired output checks are 64-bit transcripts, not an archived bytewise comparison.

Resource replay separately validates all normal batches, legal instrument
controls and any recorded insufficient-capacity/restoration pairs. R includes
the full pool, reserved stack, library and application globals/TLS/control state
and reserved external heap; serialized I/O and pool workspace are not omitted.
P includes both application and core images. Watermarks cover the executed
inputs and are not universal minimum bounds. The demonstration associates these
results only with the exact platform, core SHA-256, configuration and workspace.
Other application archives remain visible in all-results exports.

The v2 observation schema binds the compact application layout to the KEM
public-key view already embedded in its serialized secret key. Key generation
first writes its separate public-key output into the future signature buffer;
after verification, that buffer holds the ciphertext and shared secrets. This
removes 800, 1,184 or 1,568 additional bytes for the three parameter pairs.
The v1 reader preserves the earlier layout accounting when replaying archived
observations; it does not apply the v2 storage reduction to v1 records.
