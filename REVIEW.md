# CIRCL Code Review Checklist

What CI enforces, plus what a human reviewer should add. See `AGENTS.md`
for rationale.

## CI must be green

- [ ] `go build ./...` and `go test -count=1 ./...` pass on amd64 for Go
      1.25 and 1.26.
- [ ] `golangci-lint run` is clean (config: `.golangci.yaml`).
- [ ] `go vet ./...` and `go vet -vettool=shadow ./...` are clean.
- [ ] `go generate -v ./...` leaves the working tree unchanged.
- [ ] arm64, WASM (`GOOS=js GOARCH=wasm`), macOS, and Windows builds pass.
- [ ] `make circl_static` and `make circl_plugin` still work if package
      layout changed.
- [ ] CodeQL and Semgrep workflows have no new findings.

## Security

- [ ] No new secret-dependent branches, memory accesses, table indices, or
      loop bounds. `crypto/subtle` used for comparisons/selection on secrets.
- [ ] No new `unsafe` — or written justification in the commit message and
      confinement to `internal/`.
- [ ] `crypto/rand` (or an injected `io.Reader`) for randomness. No
      `math/rand` in crypto paths.
- [ ] Parsers reject malformed encodings; identity elements, zero scalars,
      zero challenges are handled explicitly (precedents: `sign/bls`,
      `ecc/bls12381`, `zk/qndleq`, `pki`).
- [ ] No new `require` entries unless already permitted by `depguard`; new
      ones include a `depguard` update.
- [ ] `gosec` findings are addressed or explicitly justified (G115 is
      pre-excluded).

## Correctness

- [ ] Implementation cites its spec — RFC, FIPS, IETF draft, or paper
      (`ia.cr/...`) — in code comments or commit message.
- [ ] Edge cases exercised: zero / one / identity / max-value inputs,
      empty slices, oversized inputs, malformed encodings.
- [ ] KATs still pass. Regenerated golden values include a written reason
      and an upstream reference (see commit `91088f2`).
- [ ] Errors are returned, not swallowed. No `panic` on
      attacker-controlled input.

## Testing

- [ ] Every bug fix has a regression test that fails without the fix.
- [ ] New crypto code has unit tests covering the documented contract.

## API and compatibility

- [ ] Exported names have godoc.
- [ ] Additive changes are preferred. Breaking changes are called out in
      the PR description and paired with `// Deprecated:` where feasible
      (see `dh/sidh`).
- [ ] No silent wire-format changes. If a serialized representation
      changes, KATs are regenerated and the change is documented.

## Code generation and assembly

- [ ] Generated packages: the **template** was edited (not the generated
      file), and `make generate` was run.
- [ ] Changed `.s` files were produced by rerunning their generator under
      `*/internal/asm/`; the diff is reproducible.
- [ ] Any new assembly path has a pure-Go fallback
      (`make NOASM=1 test` passes).

## Documentation

- [ ] Package-level godoc explains what primitive is implemented and from
      which spec.
- [ ] Non-obvious parameter choices (security level, hash, domain
      separation tag) are documented.
- [ ] New top-level packages are listed in `README.md` under the relevant
      "List of Algorithms" subsection.

---

The README disclaims API stability — "changes in the code, repository, and
API occur in the future." The bar is **"correct, justified, and
reproducible,"** not "frozen." When a change looks risky on security or
correctness grounds, request a second review from someone with
cryptographic background before merging.
