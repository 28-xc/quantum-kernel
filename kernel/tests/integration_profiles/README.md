# Integrated configuration checks

Run the Python checks from an unchanged source tree:

```text
python -B tests/integration_profiles/test_profiles.py -v
```

The checks exercise explicit recipe and backend compatibility, invalid feature
combinations, public API declaration agreement, cleanup and binding hooks, the
shared allocation-count expression, source inventory and statistical source
identities. Mutated plan identities and stale source plans must be rejected
before a compiler subprocess is reachable. Cryptographic execution and resource use are checked on the built program.

The following prepares fixed preprocessor fixtures from the actual headers and
the actual signing feature guard block:

```text
python -B tests/integration_profiles/check_c_guards.py --output ../guard-fixtures
```

To execute the fixtures through a selected compiler, use a fresh output:

```text
python -B tests/integration_profiles/check_c_guards.py --execute --cc gcc --output ../guard-results
```

This last command invokes preprocessing only. It checks successful compatible
cases and exact expected rejection diagnostics for incompatible layouts,
backends, prefix ranges and nested PCT. Its records bind the original headers,
extracted guard source, generated fixtures and command lines. Complete library
builds, mathematical oracles, API regressions and resource tests are separate
steps on the resulting program images.
