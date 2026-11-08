# `@warpgogol/intake-validator` — Agent Guide

The published consumer validator for `werkstatt:intake/v2` hand-over bundles (INTAKE-01…34). This repository is an export of the werkstatt monorepo. Do not edit it here; changes land in `packages/intake-validator` in werkstatt and are re-exported.

**Workspace type:** Package — a validator library plus the `intake-validate` bin.

## Use

```sh
intake-validate --bundle <dir> [--cost-budget-usd <n>] [--json]
```

Exit 0 means pass, 1 means the bundle has error diagnostics, and 2 means a usage error or a missing schema export. Producers pin this package exactly and run it as the `consumer.package` leg of `forge.conformance.run`.
