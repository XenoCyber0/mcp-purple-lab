## What this changes

<!-- One line: which scenario / rule / harness behaviour. -->

## Why

<!-- The attack behaviour it covers, or the detection gap it closes. -->

## Evidence

<!-- Paste the trace lines your rule matches on, with line numbers. -->

```
```

## Checks

- [ ] `python lab/summary.py` passes (coverage matrix unchanged: 3/3 attacks detected, control clean)
- [ ] `python -m unittest discover -s tests -v` passes
- [ ] No network I/O — fake local servers and `*.example` canaries only
- [ ] Files under `lab/*.py` stay under ~200 lines
