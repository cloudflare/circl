package tkn

import (
	"encoding/binary"
	"fmt"
	"io"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
)

// matrixGT represents a matrix of GT elements. They are stored in row-major order.
type matrixGT struct {
	rows    int
	cols    int
	entries []pairing.Gt
}

func (m *matrixGT) marshalBinary() ([]byte, error) {
	ret := make([]byte, 4+pairing.GtSize*m.rows*m.cols)
	binary.LittleEndian.PutUint16(ret[0:], uint16(m.rows))
	binary.LittleEndian.PutUint16(ret[2:], uint16(m.cols))
	for i := 0; i < m.rows*m.cols; i++ {
		pt, err := m.entries[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(pt) != pairing.GtSize {
			panic("matrixGT: incorrect assumption of size")
		}
		copy(ret[pairing.GtSize*i+4:], pt)
	}
	return ret, nil
}

func (m *matrixGT) unmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("matrixGT deserialization failure: input too short")
	}
	m.rows = int(binary.LittleEndian.Uint16(data[0:]))
	m.cols = int(binary.LittleEndian.Uint16(data[2:]))
	data = data[4:]
	if len(data) != pairing.GtSize*m.rows*m.cols {
		return fmt.Errorf("matrixGT deserialization failure: invalid entries length: expected %d, actual %d",
			pairing.GtSize*m.cols*m.rows,
			len(data))
	}
	m.entries = make([]pairing.Gt, m.rows*m.cols)
	var err error
	for i := 0; i < m.rows*m.cols; i++ {
		err = m.entries[i].UnmarshalBinary(data[pairing.GtSize*i : pairing.GtSize*(i+1)])
		if err != nil {
			return fmt.Errorf("matrixGT deserialization failure: error from bytes %v: %w",
				data[pairing.GtSize*i:pairing.GtSize*(i+1)],
				err)
		}
	}
	return nil
}

// exp computes the naive matrix exponential of a with respect to the basepoint.
func (m *matrixGT) exp(a *matrixZp) {
	basepoint := gtBaseVal
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].Exp(basepoint, &a.entries[i])
	}
}

// resize sets up m to be r x c
func (m *matrixGT) resize(r int, c int) {
	if m.rows != r || m.cols != c {
		m.rows = r
		m.cols = c
		m.entries = make([]pairing.Gt, m.rows*m.cols)
	}
}

// clear sets m to be the "zero" matrix
func (m *matrixGT) clear() {
	for i := 0; i < len(m.entries); i++ {
		m.entries[i].SetIdentity()
	}
}

// conformal returns true iff m and a have the same dimensions.
func (m *matrixGT) conformal(a *matrixGT) bool {
	return a.rows == m.rows && a.cols == m.cols
}

// Equal returns true if m == b.
func (m *matrixGT) Equal(b *matrixGT) bool {
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

// set sets m to b.
func (m *matrixGT) set(b *matrixGT) {
	m.resize(b.rows, b.cols)
	copy(m.entries, b.entries)
}

// add sets m to a+b.
func (m *matrixGT) add(a *matrixGT, b *matrixGT) {
	if !a.conformal(b) {
		panic(errBadMatrixSize)
	}
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].Mul(&a.entries[i], &b.entries[i])
	}
}

// leftMult multiples a*b with a matrixZp, b matrixGT.
func (m *matrixGT) leftMult(a *matrixZp, b *matrixGT) {
	if a.cols != b.rows {
		panic(errBadMatrixSize)
	}
	if m == b {
		c := newMatrixGT(a.rows, a.cols)
		c.set(b)
		b = c
	}
	m.resize(a.rows, b.cols)
	m.clear()
	tmp := &pairing.Gt{}
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			for k := 0; k < a.cols; k++ {
				tmp.Exp(&b.entries[k*b.cols+j], &a.entries[i*a.cols+k])
				m.entries[i*m.cols+j].Mul(&m.entries[i*m.cols+j], tmp)
			}
		}
	}
}

// rightMult multiplies a*b with a matrixG1, b matrixZp.
func (m *matrixGT) rightMult(a *matrixGT, b *matrixZp) {
	if a.cols != b.rows {
		panic(errBadMatrixSize)
	}
	if m == a {
		c := newMatrixGT(a.rows, a.cols)
		c.set(a)
		a = c
	}
	m.resize(a.rows, b.cols)
	m.clear()
	tmp := &pairing.Gt{}
	// to transpose can index bt[i,j] as b.entries[j*b.rows+i]
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			for k := 0; k < a.cols; k++ {
				tmp.Exp(&a.entries[i*a.cols+k], &b.entries[k*b.cols+j])
				m.entries[i*m.cols+j].Mul(&m.entries[i*m.cols+j], tmp)
			}
		}
	}
}

func newMatrixGT(r int, c int) *matrixGT {
	ret := new(matrixGT)
	ret.resize(r, c)
	ret.clear()
	return ret
}

func randomMatrixGT(rand io.Reader, r int, c int) (*matrixGT, error) {
	a, err := randomMatrixZp(rand, r, c)
	if err != nil {
		return nil, err
	}
	ret := newMatrixGT(r, c)
	ret.exp(a)
	return ret, nil
}
