# CIRCL Agent Instructions

CIRCL is an **experimental, externally visible** Go cryptographic library.
Consumers include Cloudflare's Go fork, downstream modules, and external
researchers. Every change is security-sensitive. The README disclaims API
stability — the bar is **"correct and justified,"** not "frozen."

**When in doubt, stop and ask a human maintainer.**

## Ground truth (read before acting)

- `README.md`, `go.mod`, `.golangci.yaml`, `.github/workflows/ci-actions.yml`,
  `Makefile`.

## Security

- **No new side channels.** Crypto on secret data must avoid secret-dependent
  branches, memory accesses, table indices, and loop bounds. Use
  `crypto/subtle` for comparisons and selection. Call out any deviation in
  the commit message.
- **`unsafe` is permitted but scrutinized.** Already used in
  `simd/keccakf1600`, `internal/sha3`, `dh/csidh`, `ecc/fourq`. New uses
  require written justification (perf number or interop reason) and should
  stay inside `internal/`.
- **Dependencies are allowlisted by `depguard`:** stdlib, `golang.org/x/*`,
  `github.com/bwesterb/go-ristretto`, `github.com/cloudflare/circl`. New
  entries require human approval and a `depguard` update in the same PR.
- **Randomness:** `crypto/rand` or an injected `io.Reader`. Never
  `math/rand` in crypto paths.
- **Validate inputs at API boundaries.** Recent precedents: `sign/bls`
  identity check, `ecc/bls12381` affinize identity handling, `pki` nil
  block check, `zk/qndleq` zero-challenge check.

## Testing

- **`go test ./...` must pass on amd64.** CI also runs Go 1.25/1.26 on
  arm64, WASM (`GOOS=js GOARCH=wasm`), macOS, and Windows. If you touch
  assembly or `unsafe`, also try `NOASM=1` (purego).
- **KATs:** the repo uses Known Answer Tests extensively (e.g.
  `kem/kyber/kat_test.go`, `dh/x25519/testdata/wycheproof_kat.json.gz`).
  Only regenerate a KAT with a written reason citing the upstream spec
  (see commit `91088f2` as the model).
- **Regression test every bug fix.** Recent `zk/qndleq`, `sign/bls`,
  `ecc/bls12381`, `pki` commits all follow this pattern.

## Code generation and assembly

- Several packages are **generated** (`sign/dilithium`, `sign/mldsa`,
  `kem/kyber`, `simd/keccakf1600`, `pke/kyber`). CI runs `go generate -v
  ./...` and fails if the working tree changes. Edit the `templates/` or
  `internal/.../asm/` source, then `make generate`.
- 22 `.s` files exist, generated from `avo`-style Go programs. Any new
  assembly path needs a matching pure-Go fallback for the `purego` build.

## API and compatibility

- The README says API changes are expected. Within a minor series, prefer
  **additive** changes. Breaking changes are allowed at minor-version
  boundaries; pair with `// Deprecated:` on the old API where feasible
  (see `dh/sidh`, `kem/sike`).
- **Never silently change a serialized wire format.** If you must,
  regenerate KATs and call it out loudly.
- Exported identifiers need godoc; match the surrounding package style.

## Style

- `make lint` (golangci-lint v2) enforces `gofmt`, `gofumpt`, `goimports`,
  plus `gosec`, `govet` (`enable-all` minus `fieldalignment`),
  `staticcheck`, `errcheck`, `funlen` (120/80), `unused`, `unparam`,
  `ineffassign`, `misspell`, `depguard`, and others. Run it before pushing.
- Variable shadowing is checked separately via `go vet -vettool=shadow`
  (see commit `6223887`).
- Implementation details belong in `internal/` packages. Keep the exported
  surface minimal.

## Stop and escalate immediately if you

- Suspect a **vulnerability in existing code.** Do not commit a public fix
  silently. Report via HackerOne or `security@cloudflare.com` (see README
  Security Disclaimer). Coordinated disclosure, not a normal PR.
- Are about to introduce **new `unsafe`, new `reflect`, new assembly, or a
  new external dependency.**
- Find an **ambiguity in the spec/RFC/paper** you're implementing — cite
  it and ask.
- Are about to **change a wire format, a KAT, or a public API signature.**
- Are about to **touch a secret-handling path** and are not certain the
  change preserves constant-time behavior.

This code may be deployed in TLS stacks, signing infrastructure, and
post-quantum experiments. Treat every diff as if a cryptographer will read
it on Monday.
