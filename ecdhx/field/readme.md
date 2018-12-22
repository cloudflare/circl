# field

This package contains optimized implementations of Fp25519 and FpX448 field arithmetic for amd64 architectures.

### Tests

To run a batch of tests run the following commands

````
 $ cd circl
 $ GOCACHE=off go test -v -cover
````

### Benchmark

To run a batch of benchmarking functions run the following commands

````
 $ cd circl
 $ go test -v -run=$^ -bench=. -benchmem
````
