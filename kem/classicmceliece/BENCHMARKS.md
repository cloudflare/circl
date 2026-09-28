# Classic McEliece Round 4 benchmarks

Benchmarks are centralized in `kem/classicmceliece/bench_test.go` rather than generated into each parameter-set package. The generated parameter-set packages contain implementation code only.

After changing generator templates, regenerate with:

```sh
go generate ./kem/classicmceliece
gofmt -w kem/classicmceliece
go test ./kem/classicmceliece/...
```

## Recommended benchmark commands

Run all high-level benchmarks from the consolidated benchmark file:

```sh
go test -run '^$' -bench . -benchmem ./kem/classicmceliece
```

Run representative operations for all parameter sets with one iteration each:

```sh
go test -run '^$' \
  -bench 'Benchmark(DeriveKeyPair|EncapsulateDeterministically|Decapsulate|UnmarshalPrivateKeyRecoverPublic)$' \
  -benchmem -benchtime=1x \
  ./kem/classicmceliece
```

Run one operation for one parameter set:

```sh
go test -run '^$' \
  -bench '^BenchmarkEncapsulateDeterministically/mceliece348864f$' \
  -benchmem -benchtime=10x \
  ./kem/classicmceliece
```

Generate a CPU profile for a high-level operation:

```sh
go test -run '^$' \
  -bench '^BenchmarkUnmarshalPrivateKeyRecoverPublic/mceliece8192128f$' \
  -benchmem -benchtime=3x \
  -cpuprofile mceliece.pprof \
  ./kem/classicmceliece
go tool pprof -top mceliece.pprof
```

## Benchmarks included

The consolidated benchmark file includes sub-benchmarks for all ten Round 4 parameter sets:

- `BenchmarkDeriveKeyPair/<variant>`
- `BenchmarkEncapsulateDeterministically/<variant>`
- `BenchmarkDecapsulate/<variant>`
- `BenchmarkMarshalPublicKey/<variant>`
- `BenchmarkUnmarshalPublicKey/<variant>`
- `BenchmarkMarshalPrivateKey/<variant>`
- `BenchmarkUnmarshalPrivateKeyRecoverPublic/<variant>`
- `BenchmarkPrivateKeyPublic/<variant>`

## Bottleneck summary from the scalar Go port

The dominant costs are:

1. Public-key generation and public-key recovery. `pkGen` and `pkGenFromSK` dominate key generation and private-key unmarshal. The cost comes mainly from building the generator matrix and running bit-matrix Gaussian elimination over `PKNRows * SysN/8` bytes. This is also why `UnmarshalBinaryPrivateKey` is expensive: the official compact secret key does not store the public key, so the wrapper reconstructs it.

2. Decapsulation. Decapsulation is much slower than encapsulation. The dominant internal work is `decrypt`, especially syndrome computation, root/evaluation work, and GF multiplication. It also runs `supportGen`, but support generation is smaller than the full decrypt path.

3. Encapsulation. Encapsulation is relatively cheap. The internal breakdown shows `syndrome` dominates `encrypt`; error-vector generation is minor in comparison.

4. Marshal/unmarshal copying. Public-key marshal, public-key unmarshal, and `PrivateKey.Public()` are linear copies of very large public keys. They are not algorithmic hot spots, but they allocate and copy hundreds of KiB to over 1 MiB per call.

5. Non-`f` key generation variance. Non-`f` variants can be much slower for some deterministic seeds because key generation retries until `pkGen` succeeds without the `f` pivot-column handling. The `f` variants are more stable for the seeds used in these benchmarks.

The most useful optimization targets are therefore:

- optimize `pkGen` / `pkGenFromSK` matrix elimination and row operations;
- avoid repeated public-key recovery where API usage permits storing or caching the public key;
- optimize syndrome computation in encapsulation and decapsulation;
- reduce allocations around SHAKE readers and output buffers;
- consider architecture-specific vectorized row operations behind build tags after the scalar code has been reviewed.

## Assembly acceleration

The masked GF(2) row addition that dominates `pkGen` / `pkGenFromSK` Gaussian
elimination is factored into `internal/matops.AddMasked`. On `amd64` the
dispatcher selects the widest kernel the CPU supports — AVX-512 (64-byte ZMM
blocks, preferred), then AVX2 (32-byte YMM blocks) — with a word-wise generic
tail; every other target and the `purego` build tag use the constant-time
word-wise Go fallback. Both asm kernels are avo-generated. All paths process the
full buffer regardless of the secret pivot mask, so no data-dependent branching
is introduced.

Per-tier throughput on a 1 KiB row (AMD Ryzen AI 9 HX PRO 370, Zen 5):

| Tier    | ns/op | throughput |
|---------|------:|-----------:|
| AVX-512 | 11.2  |  ~91.5 GB/s |
| AVX2    | 18.3  |  ~56.1 GB/s |
| generic | 97.3  |  ~10.5 GB/s |

Measured key generation (`-benchtime 3x`), by dispatch tier:

| Variant         | AVX-512 (ns/op) | AVX2 (ns/op) | purego (ns/op) |
|-----------------|----------------:|-------------:|---------------:|
| mceliece348864  |     123_512_019 |  131_432_931 |    337_378_882 |
| mceliece460896  |     121_984_460 |  161_116_719 |    441_613_023 |
| mceliece6688128 |     174_912_149 |  216_709_804 |    667_547_902 |
| mceliece8192128 |     213_805_287 |  272_053_739 |  1_072_751_709 |

Relative to the original scalar byte-wise loop, key generation for
`mceliece6688128` improved from ~1.47s to ~0.17s (~8.4x) with AVX-512
(~6.8x with AVX2, ~2.2x with the purego fallback).
