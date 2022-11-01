package tkn

import (
	"encoding/binary"
	"fmt"
	"io"

	pairing "github.com/cloudflare/circl/ecc/bls12381"
	"golang.org/x/crypto/blake2b"
)

// matrixZp represents a matrix of mod grouporder  elements. They are stored in row-major order.
// The name is a gesture toward the paper.
type matrixZp struct {
	rows    int
	cols    int
	entries []pairing.Scalar
}

func (m *matrixZp) marshalBinary() ([]byte, error) {
	ret := make([]byte, 4+pairing.ScalarSize*m.rows*m.cols)
	binary.LittleEndian.PutUint16(ret[0:], uint16(m.rows))
	binary.LittleEndian.PutUint16(ret[2:], uint16(m.cols))
	for i := 0; i < m.rows*m.cols; i++ {
		pt, err := m.entries[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(pt) != pairing.ScalarSize {
			panic("matrixZp: incorrect assumption of size")
		}
		copy(ret[pairing.ScalarSize*i+4:], pt)
	}
	return ret, nil
}

func (m *matrixZp) unmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("matrixZp deserialization failure: input too short")
	}
	m.rows = int(binary.LittleEndian.Uint16(data[0:]))
	m.cols = int(binary.LittleEndian.Uint16(data[2:]))
	data = data[4:]
	if len(data) != pairing.ScalarSize*m.rows*m.cols {
		return fmt.Errorf("matrixZp deserialization failure: invalid entries length: expected %d, actual %d",
			pairing.ScalarSize*m.cols*m.rows,
			len(data))
	}
	m.entries = make([]pairing.Scalar, m.rows*m.cols)
	var err error
	for i := 0; i < m.rows*m.cols; i++ {
		err = m.entries[i].UnmarshalBinary(data[pairing.ScalarSize*i : pairing.ScalarSize*(i+1)])
		if err != nil {
			return fmt.Errorf("matrixZp deserialization failure: error from bytes %v: %w",
				data[pairing.ScalarSize*i:pairing.ScalarSize*(i+1)],
				err)
		}
	}
	return nil
}

// sampleDlin samples from the distribution Dk.
// See section 3.2 of the paper for details.
func sampleDlin(rand io.Reader) (*matrixZp, error) {
	var ret matrixZp
	ret.rows = 3
	ret.cols = 2
	ret.entries = make([]pairing.Scalar, 6)
	err := ret.entries[0].Random(rand)
	if err != nil {
		return nil, err
	}
	ret.entries[1].SetUint64(0)
	ret.entries[2].SetUint64(0)
	err = ret.entries[3].Random(rand)
	if err != nil {
		return nil, err
	}
	ret.entries[4].SetOne()
	ret.entries[5].SetOne()

	return &ret, nil
}

func randomMatrixZp(rand io.Reader, r int, c int) (*matrixZp, error) {
	ret := newMatrixZp(r, c)
	for i := 0; i < r*c; i++ {
		err := ret.entries[i].Random(rand)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// We adopt the interface that math.Big uses
// Receivers get set to the results of operations, and return themselves.
// All aliases are allowed.

// Now recall that G1, G2, GT are acted on by Zp.
// So we don't have all products, just left and right with Zp.
// Zp doesn't need this distinction.

// Errors are signalled by returning nil, which propagates.

// initialize sets up m to be r x c
func (m *matrixZp) resize(r int, c int) {
	if m.rows != r || m.cols != c {
		m.rows = r
		m.cols = c
		m.entries = make([]pairing.Scalar, m.rows*m.cols)
	}
}

// clear makes m an all 0
func (m *matrixZp) clear() {
	for i := 0; i < len(m.entries); i++ {
		m.entries[i] = pairing.Scalar{}
	}
}

func newMatrixZp(r int, c int) *matrixZp {
	ret := new(matrixZp)
	ret.resize(r, c)
	ret.clear()
	return ret
}

// eye returns the k by k identity matrix.
func eye(k int) *matrixZp {
	ret := newMatrixZp(k, k)
	for i := 0; i < k; i++ {
		ret.entries[i*k+i].SetUint64(1)
	}
	return ret
}

// conformal returns true iff m and a have the same dimensions.
func (m *matrixZp) conformal(a *matrixZp) bool {
	return a.rows == m.rows && a.cols == m.cols
}

// Equal returns true iff m == a.
func (m *matrixZp) Equal(a *matrixZp) bool {
	if !m.conformal(a) {
		return false
	}
	for i := 0; i < m.rows*m.cols; i++ {
		if m.entries[i].IsEqual(&a.entries[i]) == 0 {
			return false
		}
	}
	return true
}

// set sets m to a.
func (m *matrixZp) set(a *matrixZp) {
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].Set(&a.entries[i])
	}
}

// add sets m to a+b.
func (m *matrixZp) add(a *matrixZp, b *matrixZp) {
	if !a.conformal(b) {
		panic(errBadMatrixSize)
	}
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].Add(&a.entries[i], &b.entries[i])
	}
}

// sub sets m to a-b.
func (m *matrixZp) sub(a *matrixZp, b *matrixZp) {
	if !a.conformal(b) {
		panic(errBadMatrixSize)
	}
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows*m.cols; i++ {
		m.entries[i].Sub(&a.entries[i], &b.entries[i])
	}
}

// mul sets m to a*b.
func (m *matrixZp) mul(a *matrixZp, b *matrixZp) {
	if a.cols != b.rows {
		panic(errBadMatrixSize)
	}
	if m == a {
		c := newMatrixZp(a.rows, a.cols)
		c.set(a)
		a = c
	}
	if m == b {
		c := newMatrixZp(b.rows, b.cols)
		c.set(b)
		b = c
	}
	m.resize(a.rows, b.cols)
	m.clear()
	t := &pairing.Scalar{}
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			for k := 0; k < a.cols; k++ {
				t.Mul(&a.entries[i*a.cols+k], &b.entries[k*b.cols+j])
				m.entries[i*m.cols+j].Add(&m.entries[i*m.cols+j], t)
			}
		}
	}
}

// transpose sets m to the transpose of a.
func (m *matrixZp) transpose(a *matrixZp) {
	if m == a {
		c := newMatrixZp(a.rows, a.cols)
		c.set(a)
		a = c
	}
	m.resize(a.cols, a.rows)

	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			m.entries[i*m.cols+j].Set(&a.entries[j*a.cols+i])
		}
	}
}

// swaprows swaps two rows.
func (m *matrixZp) swapRows(i int, j int) {
	t := &pairing.Scalar{}
	for k := 0; k < m.cols; k++ {
		t.Set(&m.entries[i*m.cols+k])
		m.entries[i*m.cols+k].Set(&m.entries[j*m.cols+k])
		m.entries[j*m.cols+k].Set(t)
	}
}

// scalerow scales a row.
func (m *matrixZp) scaleRow(alpha *pairing.Scalar, i int) {
	for k := 0; k < m.cols; k++ {
		m.entries[i*m.cols+k].Mul(&m.entries[i*m.cols+k], alpha)
	}
}

// addscaledrow takes alpha * row i and adds it to row j.
func (m *matrixZp) addScaledRow(alpha *pairing.Scalar, i int, j int) {
	tmp := &pairing.Scalar{}
	for k := 0; k < m.cols; k++ {
		tmp.Mul(alpha, &m.entries[i*m.cols+k])
		m.entries[j*m.cols+k].Add(tmp, &m.entries[j*m.cols+k])
	}
}

// inverse sets m to the inverse of a. If a is not invertible,
// the result is undefined and an error is returned.
// Aliasing safe
func (m *matrixZp) inverse(a *matrixZp) error {
	if a.rows != a.cols {
		panic(errBadMatrixSize)
	}
	// Any way we slice it we need additional storage.
	y := newMatrixZp(a.rows, 2*a.cols)
	for i := 0; i < a.rows; i++ {
		for j := 0; j < a.cols; j++ {
			y.entries[i*y.cols+j].Set(&a.entries[i*a.cols+j])
		}
		y.entries[i*y.cols+y.rows+i].SetUint64(1)
	}

	tmp := &pairing.Scalar{}
	// Gaussian elimination with pivoting begins here.
	for i := 0; i < y.rows; i++ {
		pivoted := false
	pivot:
		for j := i; j < y.rows; j++ {
			if y.entries[i*y.cols+j].IsZero() == 0 {
				y.swapRows(i, j)
				pivoted = true
				break pivot
			}
		}
		if !pivoted {
			return errMatrixNonInvertible
		}
		tmp.Inv(&y.entries[i*y.cols+i])
		y.scaleRow(tmp, i)

		for j := i + 1; j < y.rows; j++ {
			tmp.Set(&y.entries[j*y.cols+i])
			tmp.Neg()
			y.addScaledRow(tmp, i, j)
		}
	}
	// At this point the matrix is in reduced row echelon form.
	// The next step is to substitute back.

	for i := y.rows - 1; i >= 0; i-- {
		for j := i - 1; j >= 0; j-- {
			tmp.Set(&y.entries[j*y.cols+i])
			tmp.Neg()
			y.addScaledRow(tmp, i, j)
		}
	}
	m.resize(a.rows, a.cols)
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			m.entries[i*m.cols+j].Set(&y.entries[i*y.cols+m.cols+j])
		}
	}
	return nil
}

// prf computes a prf with output in pairs of 3x2 matrices
func prf(key []byte, input []byte) (*matrixZp, *matrixZp, error) {
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, key)
	if err != nil {
		return nil, nil, err
	}
	if _, err = xof.Write(input); err != nil {
		return nil, nil, err
	}
	m1 := newMatrixZp(3, 2)
	m2 := newMatrixZp(3, 2)
	for i := 0; i < m1.rows; i++ {
		for j := 0; j < m1.cols; j++ {
			local := xof.Clone()
			if _, err = local.Write([]byte(fmt.Sprintf("m1 matrix entry (%d, %d)", i, j))); err != nil {
				return nil, nil, err
			}
			err = m1.entries[i*m1.cols+j].Random(local)
			if err != nil {
				return nil, nil, err
			}
			local = xof.Clone()
			if _, err = local.Write([]byte(fmt.Sprintf("m2 matrix entry (%d, %d)", i, j))); err != nil {
				return nil, nil, err
			}
			err = m2.entries[i*m2.cols+j].Random(local)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return m1, m2, nil
}

// scalarmul sets m to a matrix a*B
func (m *matrixZp) scalarmul(a *pairing.Scalar, b *matrixZp) {
	m.resize(b.rows, b.cols)
	for i := 0; i < b.rows*b.cols; i++ {
		m.entries[i].Mul(a, &b.entries[i])
	}
}

// colsel sets m to a matrix with the selected columns.
func (m *matrixZp) colsel(a *matrixZp, cols []int) {
	if m == a {
		c := newMatrixZp(a.rows, a.cols)
		c.set(a)
		a = c
	}
	m.resize(a.rows, len(cols))
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			m.entries[i*m.cols+j].Set(&a.entries[i*a.cols+cols[j]])
		}
	}
}

func (m *matrixZp) String() string {
	var s string
	for i := 0; i < m.rows; i++ {
		for j := 0; j < m.cols; j++ {
			s += fmt.Sprintf("%v ", m.entries[i*m.cols+j].String())
		}
		s += "\n"
	}
	return s
}
