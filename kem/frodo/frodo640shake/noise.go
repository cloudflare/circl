package frodo640shake

const CDFTableLen = 13

var CDFTable [CDFTableLen]uint16 = [CDFTableLen]uint16{4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767}

func sample(sampled []uint16) {
	for i := 0; i < len(sampled); i++ {
		var gaussianSample uint16 = 0
		sign := sampled[i] & 1
		unifSample := sampled[i] >> 1

		for j := 0; j < CDFTableLen-1; j++ {
			gaussianSample += (CDFTable[j] - unifSample) >> 15
		}
		sampled[i] = ((-sign) ^ gaussianSample) + sign
	}
}
