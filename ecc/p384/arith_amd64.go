// +build amd64

package p384

import "golang.org/x/sys/cpu"

var hasBMI2 = cpu.X86.HasBMI2
