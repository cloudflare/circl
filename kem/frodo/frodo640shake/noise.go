package frodo640shake

const cdfTableLen = 13

var cdfTable [cdfTableLen]uint16 = [cdfTableLen]uint16{4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767}

// Take a uniformly distributed sample, and produce a sample in the FrodoKEM
// discrete Gaussian distribution using inverse transform sampling.
func sample(sampled []uint16) {
	for i := 0; i < len(sampled); i++ {
		var gaussianSample uint16 = 0
		sign := sampled[i] & 1
		unifSample := sampled[i] >> 1

		for j := 0; j < cdfTableLen-1; j++ {
			gaussianSample += (cdfTable[j] - unifSample) >> 15
		}
		// If sign = 1, -sign = 0xFFFF and the bits of gaussianSample
		// are flipped. Since gaussianSample is uint16, we have:
		//
		// flippedBits(gaussianSample) + 1 ≡ -gaussianSample (mod 2^16),
		//
		// and so the sign of gaussianSample is flipped.
		sampled[i] = ((-sign) ^ gaussianSample) + sign
	}
}
