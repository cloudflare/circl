package tkn

import (
	"encoding/binary"
	"fmt"
	"io"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
)

// matrixG1 represents a matrix of G1 elements. They are stored in row-major order.
type matrixG1 struct {
	rows    int
	cols    int
	entries []pairing.G1
}

func (m *matrixG1) marshalBinary() ([]byte, error) {
	ret := make([]byte, 4+pairing.G1Size*m.rows*m.cols)
	binary.LittleEndian.PutUint16(ret[0:], uint16(m.rows))
	binary.LittleEndian.PutUint16(ret[2:], uint16(m.cols))
	for i := 0; i < m.rows*m.cols; i++ {
		pt := m.entries[i].Bytes()
		if !m.entries[i].IsOnG1() {
			return nil, fmt.Errorf("matrixG1: illegal serialization attempt")
		}
		if len(pt) != pairing.G1Size {
			panic("matrixG1: incorrect assumption of size")
		}
		copy(ret[pairing.G1Size*i+4:], pt)
	}
	return ret, nil
}

func (m *matrixG1) unmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("matrixG1 deserialization failure: input too short")
	}
	m.rows = int(binary.LittleEndian.Uint16(data[0:]))
	m.cols = int(binary.LittleEndian.Uint16(data[2:]))
	data = data[4:]
	if len(data) != pairing.G1Size*m.rows*m.cols {
		return fmt.Errorf("matrixG1 deserialization failure: invalid entries length: expected %d, actual %d",
			pairing.G1Size*m.cols*m.rows,
			len(data))
	}
	m.entries = make([]pairing.G1, m.rows*m.cols)
	var err error
	for i := 0; i < m.rows*m.cols; i++ {
		err = m.entries[i].SetBytes(data[pairing.G1Size*i : pairing.G1Size*(i+1)])
		if err != nil {
			return fmt.Errorf("matrixG1 deserialization failure: error from bytes %v: %w",
				data[pairing.G1Size*i:pairing.G1Size*(i+1)],
				err)
		}
	}
	return nil
}

// We write addition for each of these, multiplication by scalars, and action on both
// sides?

// exp computes the naive matrix exponential of a with respect to the basepoint.
func (m *matrixG1) exp(a *matrixZp) {
	basepoint := pairing.G1Generator()
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].ScalarMult(&a.entries[i], basepoint)
	}
}

// resize only changes the matrix if we have to
func (m *matrixG1) resize(r int, c int) {
	if m.rows != r || m.cols != c {
		m.rows = r
		m.cols = c
		m.entries = make([]pairing.G1, m.rows*m.cols)
	}
}

// clear sets a matrix to the all zero matrix
func (m *matrixG1) clear() {
	for i := 0; i < len(m.entries); i++ {
		m.entries[i].SetIdentity()
	}
}

// conformal returns true iff m and a have the same dimensions.
func (m *matrixG1) conformal(a *matrixG1) bool {
	return a.rows == m.rows && a.cols == m.cols
}

// Equal returns true if m == b.
func (m *matrixG1) Equal(b *matrixG1) bool {
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
func (m *matrixG1) set(a *matrixG1) {
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i] = a.entries[i]
	}
}

// add sets m to a+b.
func (m *matrixG1) add(a *matrixG1, b *matrixG1) {
	if !a.conformal(b) {
		panic(errBadMatrixSize)
	}
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].Add(&a.entries[i], &b.entries[i])
	}
}

// sub sets m to a-b.
func (m *matrixG1) sub(a *matrixG1, b *matrixG1) {
	if !a.conformal(b) {
		panic(errBadMatrixSize)
	}
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		t := b.entries[i]
		t.Neg()
		m.entries[i].Add(&a.entries[i], &t)
	}
}

// leftMult multiples a*b with a matrixZp, b matrixG1.
func (m *matrixG1) leftMult(a *matrixZp, b *matrixG1) {
	if a.cols != b.rows {
		panic(errBadMatrixSize)
	}
	if b == m {
		c := newMatrixG1(0, 0)
		c.set(b)
		b = c
	}
	m.resize(a.rows, b.cols)
	m.clear()
	var t pairing.G1
	t.SetIdentity()
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			for k := 0; k < a.cols; k++ {
				t.ScalarMult(&a.entries[i*a.cols+k], &b.entries[k*b.cols+j])
				m.entries[i*m.cols+j].Add(&m.entries[i*m.cols+j], &t)
			}
		}
	}
}

// rightMult multiplies a*b with a matrixG1, b matrixZp.
func (m *matrixG1) rightMult(a *matrixG1, b *matrixZp) {
	if a.cols != b.rows {
		panic(errBadMatrixSize)
	}
	if a == m {
		c := newMatrixG1(0, 0)
		c.set(a)
		a = c
	}
	m.resize(a.rows, b.cols)
	m.clear()
	var t pairing.G1
	t.SetIdentity()
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			for k := 0; k < a.cols; k++ {
				t.ScalarMult(&b.entries[k*b.cols+j], &a.entries[i*a.cols+k])
				m.entries[i*m.cols+j].Add(&m.entries[i*m.cols+j], &t)
			}
		}
	}
}

// scalarMult sets m to c*a where c is a Scalar,
func (m *matrixG1) scalarMult(c *pairing.Scalar, a *matrixG1) {
	m.resize(a.rows, a.cols)
	for i := 0; i < len(a.entries); i++ {
		m.entries[i].ScalarMult(c, &a.entries[i])
	}
}

// copy creates and returns a new matrix that shares no storage with m
func (m *matrixG1) copy() *matrixG1 {
	ret := new(matrixG1)
	ret.resize(m.rows, m.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		ret.entries[i] = m.entries[i]
	}
	return ret
}

func newMatrixG1(r int, c int) *matrixG1 {
	ret := new(matrixG1)
	ret.resize(r, c)
	ret.clear()
	return ret
}

func randomMatrixG1(rand io.Reader, r int, c int) (*matrixG1, error) {
	a, err := randomMatrixZp(rand, r, c)
	if err != nil {
		return nil, err
	}
	ret := newMatrixG1(r, c)
	ret.exp(a)
	return ret, nil
}

// oracle generates 3x2 matrices via the random oracle
func oracle(input []byte) (*matrixG1, *matrixG1) {
	a := newMatrixG1(3, 2)
	b := newMatrixG1(3, 2)
	for i := 0; i < 3; i++ {
		for j := 0; j < 2; j++ {
			a.entries[i*a.cols+j].Hash(input, []byte(fmt.Sprintf("a matrix entry [%d, %d]", i, j)))
			b.entries[i*b.cols+j].Hash(input, []byte(fmt.Sprintf("b matrix entry [%d, %d]", i, j)))
		}
	}
	return a, b
}

// transpose sets m to the transpose of a.
// Not aliasing safe
func (m *matrixG1) transpose(a *matrixG1) {
	if m == a {
		c := newMatrixG1(0, 0)
		c.set(a)
		a = c
	}
	m.resize(a.cols, a.rows)

	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			m.entries[i*m.cols+j] = a.entries[j*a.cols+i]
		}
	}
}
