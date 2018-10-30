## fp25519

The fp25519 package brings optimized prime field arithmetic for p=2^255-19 prime. This is a port from  [rfc7748_precomputed](https://github.com/armfazh/rfc7748_precomputed), a C optimized code for AMD64 architectures.

### Features

* Fast and optimized code for AMD64 architecture.
* Constant-time implementation.
* Zero dynamic memory allocations. No variables escape to the heap.
* It supports MULX+ADX fast integer instructions; otherwise, it fallbacks to common 64-bit instructions.


### Copyright & License

`fp25519` package is released under the BSD 3-Clause license. See [LICENSE](../LICENSE)

### Contributors

* Armando Faz Hernandez.
* Jason A. Donenfeld.
* Samuel Neves.

### Research

*"How to (Pre-)Compute a Ladder"* - SAC'2017  [[paper]](https://doi.org/10.1007/978-3-319-72565-9_9) [[eprint]](https://ia.cr/2017/264)


### Issues and Improvements

Use the [issues](../issues) web page for comments and questions.
