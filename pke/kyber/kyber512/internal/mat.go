package internal

// A k by k matrix of polynomials.
type Mat [K]Vec

// Expands the given seed to the corresponding matrix A or its transpose Aᵀ.
func (m *Mat) Derive(seed *[32]byte, transpose bool) {
	if transpose {
		for i := 0; i < K; i++ {
			for j := 0; j < K; j++ {
				m[i][j].DeriveUniform(seed, uint8(i), uint8(j))
			}
		}
	} else {
		for i := 0; i < K; i++ {
			for j := 0; j < K; j++ {
				m[i][j].DeriveUniform(seed, uint8(j), uint8(i))
			}
		}
	}
}

// Tranposes A in place.
func (m *Mat) Transpose() {
	for i := 0; i < K-1; i++ {
		for j := i + 1; j < K; j++ {
			t := m[i][j]
			m[i][j] = m[j][i]
			m[j][i] = t
		}
	}
}
