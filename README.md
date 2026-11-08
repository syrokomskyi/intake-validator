# @warpgogol/intake-validator

The validator for `werkstatt:intake/v2` hand-over bundles (rules INTAKE-01…34) — the same code werkstatt runs in `onboarding.intake.validate`.

```sh
npx intake-validate --bundle ./out/intake --json
```

- Exit `0` means the bundle passes, `1` means it has error diagnostics, and `2` means a usage error or a missing schema export.
- The JSON payload is werkstatt's `onboarding.intake.validate` result plus `validator: { package, version }`.
- A producer pins this package as an exact devDependency and declares it as `consumer.package` in `forge.yaml` `contractProducers[]`. See Forge `forge.conformance.run` (RFC-1539).
- The producer's vendored `intake.schema.generated.yaml` must come from the same `@warpgogol/werkstatt-shared` version this package depends on; otherwise INTAKE-10 fails.
