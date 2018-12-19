# ECDHX

This package contains optimized implementations of X25519 and X448 for amd64 architectures.

### Installation

This library requires to generated some files, to do that run

````
 $ cd circl
 $ go generate -v ./...
````

and this will generate several files.

### Tests

To run a batch of tests run the following commands

````
 $ cd circl
 $ GOCACHE=off go test -v -short -cover ./...
````
There is a couple of long tests that can be executed by removing the flag `-short`.

### Benchmark

To run a batch of benchmarking functions run the following commands

````
 $ cd circl
 $ go test -v -run=$^ -bench=. -benchmem ./...
````


### The `field` package

The `field` package provides prime field arithmetic over GF(2^255-19) and GF(2^448-2^224-1).
