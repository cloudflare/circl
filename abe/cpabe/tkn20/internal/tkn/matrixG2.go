package tkn

import (
	"encoding/binary"
	"fmt"
	"io"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
)

// matrixG2 represents a matrix of G2 elements. They are stored in row-major order.
type matrixG2 struct {
	rows    int
	cols    int
	entries []pairing.G2
}

func (m *matrixG2) marshalBinary() ([]byte, error) {
	ret := make([]byte, 4+pairing.G2Size*m.rows*m.cols)
	binary.LittleEndian.PutUint16(ret[0:], uint16(m.rows))
	binary.LittleEndian.PutUint16(ret[2:], uint16(m.cols))
	for i := 0; i < m.rows*m.cols; i++ {
		pt := m.entries[i].Bytes()
		if len(pt) != pairing.G2Size {
			return nil, errBadMatrixSize
		}
		copy(ret[pairing.G2Size*i+4:], pt)
	}
	return ret, nil
}

func (m *matrixG2) unmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("matrixG2 deserialization failure: input too short")
	}
	m.rows = int(binary.LittleEndian.Uint16(data[0:]))
	m.cols = int(binary.LittleEndian.Uint16(data[2:]))
	data = data[4:]
	if len(data) != pairing.G2Size*m.rows*m.cols {
		return fmt.Errorf("matrixG2 deserialization failure: invalid entries length: expected %d, actual %d",
			pairing.G2Size*m.cols*m.rows,
			len(data))
	}
	m.entries = make([]pairing.G2, m.rows*m.cols)
	var err error
	for i := 0; i < m.rows*m.cols; i++ {
		err = m.entries[i].SetBytes(data[pairing.G2Size*i : pairing.G2Size*(i+1)])
		if err != nil {
			return fmt.Errorf("matrixG2 deserialization failure: error from bytes %v: %w",
				data[pairing.G2Size*i:pairing.G2Size*(i+1)],
				err)
		}
	}
	return nil
}

// exp computes the naive matrix exponential of a with respect to the basepoint.
func (m *matrixG2) exp(a *matrixZp) {
	basepoint := pairing.G2Generator()
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].ScalarMult(&a.entries[i], basepoint)
	}
}

// clear sets m to the zero matrix
func (m *matrixG2) clear() {
	for i := 0; i < len(m.entries); i++ {
		m.entries[i].SetIdentity()
	}
}

// resize only changes the matrix if we have to
func (m *matrixG2) resize(r int, c int) {
	if m.rows != r || m.cols != c {
		m.rows = r
		m.cols = c
		m.entries = make([]pairing.G2, m.rows*m.cols)
	}
}

// conformal returns true iff m and a have the same dimensions.
func (m *matrixG2) conformal(a *matrixG2) bool {
	return a.rows == m.rows && a.cols == m.cols
}

// Equal returns true if m == b.
func (m *matrixG2) Equal(b *matrixG2) bool {
	if !m.conformal(b) {
		return false
	}
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			if !m.entries[i*m.cols+j].IsEqual(&b.entries[i*b.cols+j]) {
				return false
			}
		}
	}
	return true
}

// set sets m to a.
func (m *matrixG2) set(a *matrixG2) {
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i] = a.entries[i]
	}
}

// add sets m to a+b.
func (m *matrixG2) add(a *matrixG2, b *matrixG2) {
	if !a.conformal(b) {
		panic(errBadMatrixSize)
	}
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].Add(&a.entries[i], &b.entries[i])
	}
}

// leftMult multiples a*b with a matrixZp, b matrixG2.
func (m *matrixG2) leftMult(a *matrixZp, b *matrixG2) {
	if a.cols != b.rows {
		panic(errBadMatrixSize)
	}
	if m == b {
		c := newMatrixG2(b.rows, b.cols)
		c.set(b)
		b = c
	}
	m.resize(a.rows, b.cols)
	m.clear()
	var tmp pairing.G2
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			for k := 0; k < a.cols; k++ {
				tmp.ScalarMult(&a.entries[i*a.cols+k], &b.entries[k*b.cols+j])
				m.entries[i*m.cols+j].Add(&m.entries[i*m.cols+j], &tmp)
			}
		}
	}
}

// rightMult multiplies a*b with a matrixG1, b matrixZp.
func (m *matrixG2) rightMult(a *matrixG2, b *matrixZp) {
	if a.cols != b.rows {
		panic(errBadMatrixSize)
	}
	if m == a {
		c := newMatrixG2(a.rows, a.cols)
		c.set(a)
		a = c
	}
	m.resize(a.rows, b.cols)
	m.clear()
	var tmp pairing.G2
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			for k := 0; k < a.cols; k++ {
				tmp.ScalarMult(&b.entries[k*b.cols+j], &a.entries[i*a.cols+k])
				m.entries[i*m.cols+j].Add(&m.entries[i*m.cols+j], &tmp)
			}
		}
	}
}

func newMatrixG2(r int, c int) *matrixG2 {
	ret := new(matrixG2)
	ret.resize(r, c)
	ret.clear()
	return ret
}

func randomMatrixG2(rand io.Reader, r int, c int) (*matrixG2, error) {
	a, err := randomMatrixZp(rand, r, c)
	if err != nil {
		return nil, err
	}
	ret := newMatrixG2(r, c)
	ret.exp(a)
	return ret, nil
}
