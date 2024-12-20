// Package prio3 implements Prio3, a set of Verifiable Distributed
// Aggregation Functions (VDAFs). It provides several concrete VDAFs
// described in draft-irtf-cfrg-vdaf [v13]:
//   - Count [github.com/cloudflare/circl/vdaf/prio3/count]
//   - Sum [github.com/cloudflare/circl/vdaf/prio3/sum]
//   - SumVec [github.com/cloudflare/circl/vdaf/prio3/sumvec]
//   - Histogram [github.com/cloudflare/circl/vdaf/prio3/mhcv]
//   - MultiHotCountVec [github.com/cloudflare/circl/vdaf/prio3/histogram]
//
// [v13]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vdaf-13
package prio3
