# Changelog

All notable changes to the TraitX Go SDK are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the module
uses [Semantic Versioning](https://semver.org/). Releases are Git tags of the
form `vX.Y.Z` on this repository; `traitx.Version` must equal the tag.

## [Unreleased]

### Changed
- `go.mod` now declares `go 1.22` (was `go 1.19`, which is no longer supported
  upstream). No API changes; the SDK still uses only the standard library.
- Added GitHub Actions: `ci.yml` (vet, build, unit + conformance tests on
  Go 1.22 / 1.23 / stable) and a tag-gated `release.yml`.

## [1.0.0] - 2026-08-18

Initial release of the TraitX decision SDK for Go.

### Added
- `traitx.New(Config)` client with `Evaluate`, `EvaluateLogin`,
  `EvaluateRegistration`, `EvaluateTransaction` and friends: evaluate a risk
  event against the tenant's policy chain and get `allow` / `challenge` / `deny`.
- Decision resolution per `SPEC.md` (thresholds, signal escalation, shadow-mode
  policies, degraded and client-error failure modes), verified against the
  shared `conformance/vectors.json`.
- Transport with per-attempt timeouts, retry with full jitter, `Retry-After`
  handling and a circuit breaker.
- Management client (policies and lists) authenticated with a portal JWT.
- `cmd/doctor` connectivity checker and an `example/` HTTP integration.

[Unreleased]: https://github.com/traitx-allytech/traitx-sdk-go/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/traitx-allytech/traitx-sdk-go/releases/tag/v1.0.0
