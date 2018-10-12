// +build amd64,!noasm

// Sets capabilities flags for x86 according to information received from
// CPUID. It was written in accordance with
// "Intel® 64 and IA-32 Architectures Developer's Manual: Vol. 2A".
// https://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-software-developer-vol-2a-manual.html

package utils

// Signals support for MULX which is in BMI2
var HasBMI2 bool

// Signals support for ADX and BMI2
var HasADXandBMI2 bool

// Performs CPUID and returns values of registers
// go:nosplit
func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// Returns true in case bit 'n' in 'bits' is set, otherwise false
func bitn(bits uint32, n uint8) bool {
	return (bits>>n)&1 == 1
}

func RecognizeCpu() {
	// CPUID returns max possible input that can be requested
	max, _, _, _ := cpuid(0, 0)
	if max < 7 {
		return
	}

	_, ebx, _, _ := cpuid(7, 0)
	HasBMI2 = bitn(ebx, 19)
	HasADXandBMI2 = bitn(ebx, 7) && HasBMI2
}

func init() {
	RecognizeCpu()
}
