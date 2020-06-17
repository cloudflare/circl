package ff

import "fmt"

// Cyclo12 represents an element of the 12-th cyclotomic group.
type Cyclo12 [2]Fp6

func (z Cyclo12) String() string { return fmt.Sprintf("\n0: %v\n1: %v", z[0], z[1]) }
