# Changelog

All notable changes to `@warpgogol/intake-validator` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-11-08

### Added

- First release: the `werkstatt:intake/v2` consumer rules (INTAKE-01…34), the same code werkstatt runs in `onboarding.intake.validate`.
- `intake-validate --bundle <dir> [--cost-budget-usd <n>] [--json]`: exit 0 means pass, 1 means error diagnostics, 2 means a usage error or a missing schema export. The JSON payload adds `validator: { package, version }`.
- The family visitor-question export ships in `data/`, and the package declares `"forge": { "conformanceValidator": true }` for Forge's CONF-09.
