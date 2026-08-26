package bbs

import (
	"crypto"
	"encoding/binary"
	"encoding/hex"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/expander"
	"github.com/cloudflare/circl/xof"
)

// SuiteID identifies the suite of algorithms supported.
type SuiteID uint

const (
	// Corresponds to the "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_" suite.
	SuiteBLS12381Shake256 SuiteID = iota
	// Corresponds to the "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_" suite.
	SuiteBLS12381Sha256

	maxSuiteID
)

func (id SuiteID) String() string { id.check(); return suiteIDName[id] }

func (id SuiteID) check() {
	if id >= maxSuiteID {
		panic(ErrInvalidSuiteID)
	}
}

func (id SuiteID) new() suite {
	id.check()
	var b [50]byte
	return suite{
		SuiteID: id,
		gens:    &suiteGenerators[id],
		prefix:  append(append(b[:0], suiteIDName[id]...), labelAPIID...),
	}
}

type suite struct {
	gens   *precmpGens
	prefix []byte
	SuiteID
}

func (s suite) apiID() []byte           { return s.prefix }
func (s suite) keyDST() []byte          { return []byte(s.String() + labelKeyDST) }
func (s suite) HashToScalarDST() []byte { return append(s.prefix, labelHashToScalarDST...) }
func (s suite) SeedDST() []byte         { return append(s.prefix, labelSeedDST...) }
func (s suite) GeneratorDST() []byte    { return append(s.prefix, labelGeneratorDST...) }
func (s suite) GeneratorSeed() []byte   { return append(s.prefix, labelGeneratorSeed...) }
func (s suite) BpGeneratorSeed() []byte { return append(s.prefix, labelBpGeneratorSeed...) }
func (s suite) MapDST() []byte          { return append(s.prefix, labelMapDST...) }
func (s suite) getP1() (g g1)           { return fetchG1FromString(s.gens.P1) }
func (s suite) newHasherScalar(dst []byte) (h hasherScalar) {
	switch s.SuiteID {
	case SuiteBLS12381Sha256:
		h.exp = expander.NewExpanderMD(crypto.SHA256, dst)
	case SuiteBLS12381Shake256:
		const SecLevel = 128
		h.exp = expander.NewExpanderXOF(xof.SHAKE256, SecLevel, dst)
	}
	h.r.SetBytes(bls12381.Order())
	return h
}

func (s suite) hashToScalar(msg, dst []byte) bufScalar {
	h := s.newHasherScalar(dst)
	return h.Hash(msg)
}

func (s suite) hashToGenerators(gens []g1, generatorSeed []byte, start uint) {
	var expBytes, expHashG1 expander.Expander
	switch s.SuiteID {
	case SuiteBLS12381Sha256:
		const h = crypto.SHA256
		expBytes = expander.NewExpanderMD(h, s.SeedDST())
		expHashG1 = expander.NewExpanderMD(h, s.GeneratorDST())
	case SuiteBLS12381Shake256:
		const SecLevel = 128
		const f = xof.SHAKE256
		expBytes = expander.NewExpanderXOF(f, SecLevel, s.SeedDST())
		expHashG1 = expander.NewExpanderXOF(f, SecLevel, s.GeneratorDST())
	}

	v := expBytes.Expand(generatorSeed, expandLen)
	for i := range gens {
		v = expBytes.Expand(
			binary.BigEndian.AppendUint64(v, uint64(i+1)), expandLen)
		if uint(i) >= start {
			gens[i].HashWithExpander(expHashG1, v)
		}
	}
}

func (s suite) getQ1Gens(g []g1) {
	numGen := len(g)
	numPrecmp := len(s.gens.Q1Gens)
	n := min(numGen, numPrecmp)
	for i := range n {
		g[i] = fetchG1FromString(s.gens.Q1Gens[i])
	}

	if numGen > numPrecmp {
		s.hashToGenerators(g, s.GeneratorSeed(), uint(numPrecmp))
	}
}

func fetchG1FromString(str string) (g g1) {
	var b [g1Size]byte
	_, err := hex.Decode(b[:], []byte(str))
	if err != nil {
		panic(ErrGenerators)
	}

	err = g.SetBytes(b[:])
	if err != nil {
		panic(err)
	}

	return g
}

type (
	g1         = bls12381.G1
	g2         = bls12381.G2
	scalar     = bls12381.Scalar
	precmpGens struct {
		P1     string
		Q1Gens [numPrecmpGens]string // First is Q1, others are H_i.
	}
)

const (
	g1Size                = bls12381.G1SizeCompressed
	g2Size                = bls12381.G2SizeCompressed
	scalarSize            = bls12381.ScalarSize
	suiteBLS12381Sha256   = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
	suiteBLS12381Shake256 = "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
	labelKeyDST           = "KEYGEN_DST_"
	labelAPIID            = "H2G_HM2S_"
	labelHashToScalarDST  = "H2S_"
	labelSeedDST          = "SIG_GENERATOR_SEED_"
	labelGeneratorDST     = "SIG_GENERATOR_DST_"
	labelGeneratorSeed    = "MESSAGE_GENERATOR_SEED"
	labelBpGeneratorSeed  = "BP_MESSAGE_GENERATOR_SEED"
	labelMapDST           = "MAP_MSG_TO_SCALAR_AS_HASH_"
	expandLen             = 48
	numPrecmpGens         = 5
)

var (
	suiteIDName = [...]string{
		SuiteBLS12381Shake256: suiteBLS12381Shake256,
		SuiteBLS12381Sha256:   suiteBLS12381Sha256,
	}

	suiteGenerators = [...]precmpGens{
		SuiteBLS12381Shake256: {
			P1: "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755",
			Q1Gens: [numPrecmpGens]string{
				"a9d40131066399fd41af51d883f4473b0dcd7d028d3d34ef17f3241d204e28507d7ecae032afa1d5490849b7678ec1f8",
				"903c7ca0b7e78a2017d0baf74103bd00ca8ff9bf429f834f071c75ffe6bfdec6d6dca15417e4ac08ca4ae1e78b7adc0e",
				"84321f5855bfb6b001f0dfcb47ac9b5cc68f1a4edd20f0ec850e0563b27d2accee6edff1a26b357762fb24e8ddbb6fcb",
				"b3060dff0d12a32819e08da00e61810676cc9185fdd750e5ef82b1a9798c7d76d63de3b6225d6c9a479d6c21a7c8bf93",
				"8f1093d1e553cdead3c70ce55b6d664e5d1912cc9edfdd37bf1dad11ca396a0a8bb062092d391ebf8790ea5722413f68",
			},
		},
		SuiteBLS12381Sha256: {
			P1: "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9",
			Q1Gens: [numPrecmpGens]string{
				"a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be",
				"98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4",
				"a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a",
				"b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62",
				"ac0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe20035",
			},
		},
	}
)
