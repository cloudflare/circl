package csidh

const (
	// pbits is a bitsize of prime p
	pbits = 511
	// primeCount number of Elkies primes used for constructing p
	primeCount = 74
	// (2*5+1)^74 is roughly 2^256
	expMax = int8(5)
	// size of the limbs, pretty much hardcoded to 64-bit words
	limbBitSize = 64
	// size of the limbs in bytes
	limbByteSize = limbBitSize >> 3
	// Number of limbs for a field element
	numWords = 8
	// PrivateKeySize is a size of cSIDH/512 private key in bytes.
	PrivateKeySize = 37
	// PublicKeySize is a size of cSIDH/512 public key in bytes.
	PublicKeySize = 64
	// SharedSecretSize is a size of cSIDH/512 shared secret in bytes.
	SharedSecretSize = 64
)

var (
	// Elkies primes up to 374 + prime 587
	// p = 4 * product(Elkies primes) - 1
	primes = [primeCount]uint64{
		0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013, 0x0017, 0x001D, 0x001F, 0x0025,
		0x0029, 0x002B, 0x002F, 0x0035, 0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053,
		0x0059, 0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F, 0x0083, 0x0089, 0x008B,
		0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD, 0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5,
		0x00C7, 0x00D3, 0x00DF, 0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
		0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137, 0x0139, 0x013D, 0x014B,
		0x0151, 0x015B, 0x015D, 0x0161, 0x0167, 0x016F, 0x0175, 0x024B,
	}

	p = fp{
		0x1B81B90533C6C87B, 0xC2721BF457ACA835,
		0x516730CC1F0B4F25, 0xA7AAC6C567F35507,
		0x5AFBFCC69322C9CD, 0xB42D083AEDC88C42,
		0xFC8AB0D15E3E4C4A, 0x65B48E8F740F89BF,
	}

	/* Montgomery R = 2^512 mod p */
	one = fp{
		0xC8FC8DF598726F0A, 0x7B1BC81750A6AF95,
		0x5D319E67C1E961B4, 0xB0AA7275301955F1,
		0x4A080672D9BA6C64, 0x97A5EF8A246EE77B,
		0x06EA9E5D4383676A, 0x3496E2E117E0EC80,
	}

	// 2 in Montgomery domain
	two = fp{
		0x767762E5FD1E1599, 0x33C5743A49A0B6F6,
		0x68FC0C0364C77443, 0xB9AA1E24F83F56DB,
		0x3914101F20520EFB, 0x7B1ED6D95B1542B4,
		0x114A8BE928C8828A, 0x03793732BBB24F40,
	}

	// -2 in Montgomery domain
	twoNeg = fp{
		0xA50A561F36A8B2E2, 0x8EACA7BA0E0BF13E,
		0xE86B24C8BA43DAE2, 0xEE00A8A06FB3FE2B,
		0x21E7ECA772D0BAD1, 0x390E316192B3498E,
		0xEB4024E83575C9C0, 0x623B575CB85D3A7F,
	}

	// 4 in Montgomery domain
	four = fp{
		0xECEEC5CBFA3C2B32, 0x678AE87493416DEC,
		0xD1F81806C98EE886, 0x73543C49F07EADB6,
		0x7228203E40A41DF7, 0xF63DADB2B62A8568,
		0x229517D251910514, 0x06F26E6577649E80,
	}

	// 4 * sqrt(p)
	fourSqrtP = fp{
		0x17895E71E1A20B3F, 0x38D0CD95F8636A56,
		0x142B9541E59682CD, 0x856F1399D91D6592,
		0x0000000000000002,
	}

	// -p^-1 mod 2^64
	pNegInv = fp{
		0x66c1301f632e294d,
	}

	// (p-1)/2. Used as exponent, hence not in
	// montgomery domain
	pMin1By2 = fp{
		0x8DC0DC8299E3643D, 0xE1390DFA2BD6541A,
		0xA8B398660F85A792, 0xD3D56362B3F9AA83,
		0x2D7DFE63499164E6, 0x5A16841D76E44621,
		0xFE455868AF1F2625, 0x32DA4747BA07C4DF,
	}

	// p-1 mod 2^64. Used as exponent, hence not
	// in montgomery domain
	pMin1 = fp{
		0x1B81B90533C6C879, 0xC2721BF457ACA835,
		0x516730CC1F0B4F25, 0xA7AAC6C567F35507,
		0x5AFBFCC69322C9CD, 0xB42D083AEDC88C42,
		0xFC8AB0D15E3E4C4A, 0x65B48E8F740F89BF,
	}
)
