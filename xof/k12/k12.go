// k12 implements the KangarooTwelve XOF.
//
// KangarooTwelve is being standardised at the CFRG working group
// of the IRTF. This package implements draft 10.
//
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/10/
package k12

import (
	"encoding/binary"
	"sync"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/simd/keccakf1600"
)

const chunkSize = 8192 // aka B

// Number of jobs to process at once in multithreaded mode
const batchSize = 4

// KangarooTwelve splits the message into chunks of 8192 bytes each.
// The first chunk is absorbed directly in a TurboSHAKE128 instance, which
// we call the stalk. The subsequent chunks aren't absorbed directly, but
// instead their hash is absorbed: they're like leafs on a stalk.
// If we have a fast TurboSHAKE128 available, we buffer chunks until we have
// enough to do the parallel TurboSHAKE128. If not, we absorb directly into
// a separate TurboSHAKE128 state.
// If requested by the user, will spin up worker threads to compute
// on multiple threads at the same time.

// State stores the intermediate state computing a Kangaroo12 hash.
type State struct {
	initialTodo int // Bytes left to absorb for the first chunk.

	stalk sha3.State

	context []byte // context string "C" provided by the user

	// buffer of incoming data so we can do parallel TurboSHAKE128:
	// nil when we haven't absorbed the first chunk yet;
	// empty if we have, but we do not have a fast parallel TurboSHAKE128;
	// and chunkSize*lanes in length if we have.
	buf []byte

	offset int // offset in buf or bytes written to leaf

	// Number of chunk hashes ("CV_i") absorbed into the stalk.
	chunk uint

	// TurboSHAKE128 instance to compute the leaf in case we don't have
	// a fast parallel TurboSHAKE128, viz when lanes == 1.
	leaf *sha3.State

	workers      int   // number of parallel workers; 1 if in single-threaded mode.
	lanes        uint8 // number of TurboSHAKE128s to compute in parallel
	maxWriteSize int   // cached return of MaxWriteSize()

	// nil if absorbing first chunk or if operating in single-threaded mode,
	// and otherwise contains all the buffers and locks to deal with the
	// multithreaded computation.
	w *workersState
}

type job struct {
	data   []byte // chunks to be hased; one for each lane
	hashes []byte // resulting hashes; one for each lane
	done   bool
}

// When in multithreaded mode, chunks to be hashed are put in jobs and
// written to a ringbuffer.  Worker threads take jobs from this ringbuffer.
// The worker threads hash the chunks and write back the resulting hashes
// into the ringbuffer. If a worker writes back a hash, that was the first
// one we were still waiting for to write to the stalk, that worker writes
// it to the stalk, and any consecutive hashes that are ready.
type workersState struct {
	// Ringbuffer with jobs. Each slot contains a copy of the data to be
	// hashed and a buffer for the result. There are three indices into
	// this ringbuffer (rOff, wOff and tOff) described below.
	ring []job

	// Reader offset in ring: the first job we're waiting for that
	// hasn't come back yet, or wOff if the ring buffer is empty.
	rOff int

	// Writer offset in ring: the first free job slot, or equal to
	// rOff-1 modulo len(ring) if the ring buffer is "full". For simplicity,
	// we always leave one free slot to distinguish between an empty and
	// full buffer.
	wOff int

	// Task offset in ring: the last slot that has been picked up by a worker.
	// Thus tOff == wOff when all tasks have been picked up.
	tOff int

	// Used to wait on the workers finishing up after no more data is going
	// to be written.
	wg sync.WaitGroup

	// Workers wait on this condition when there are no jobs to be picked up.
	// That is, when tOff = wOff.
	taskCond *sync.Cond

	// Number of workers waiting on taskCond
	taskWaiting int

	// The thread calling Write() waits on this, when the ring is full.
	writeSlotCond *sync.Cond

	// Number of workers waiting for a full ring. Should only be 0 or 1.
	writeSlotWaiting int

	// True if a worker is writing to the stalk.
	hashing bool

	mux sync.Mutex

	// True if no more data is going to be written
	noMore bool
}

// NewDraft10 creates a new instance of Kangaroo12 draft version -10.
func NewDraft10(opts ...Option) State {
	var lanes byte = 1

	if keccakf1600.IsEnabledX4() {
		lanes = 4
	} else if keccakf1600.IsEnabledX2() {
		lanes = 2
	}

	o := options{
		lanes:   lanes,
		workers: 1,
	}

	o.apply(opts)

	return newDraft10(o)
}

type options struct {
	workers int
	lanes   byte
	context []byte
}

// Option to K12, for instance WithContext([]byte("context string")).
type Option func(*options)

func (o *options) apply(opts []Option) {
	for _, opt := range opts {
		opt(o)
	}
}

// WithWorkers sets numbers of parallel threads to use in the computation.
func WithWorkers(workers int) Option {
	if workers < 1 {
		panic("Number of workers has to be strictly positive")
	}
	return func(opts *options) {
		opts.workers = workers
	}
}

// WithContext sets the context string used
func WithContext(context []byte) Option {
	return func(opts *options) {
		opts.context = context
	}
}

func newDraft10(opts options) State {
	if opts.workers == 0 {
		opts.workers = 1
	}

	mws := int(opts.lanes) * chunkSize * opts.workers

	ret := State{
		initialTodo:  chunkSize,
		stalk:        sha3.NewTurboShake128(0x07),
		context:      opts.context,
		lanes:        opts.lanes,
		workers:      opts.workers,
		maxWriteSize: mws,
	}

	return ret
}

// Entrypoint of a worker goroutine in multithreaded mode.
// See workersState for an overview of the concurrency pattern used.
func (s *State) worker() {
	s.w.mux.Lock()
	for {
		for s.w.tOff == s.w.wOff && !s.w.noMore {
			s.w.taskWaiting++
			s.w.taskCond.Wait()
			s.w.taskWaiting--
		}

		if s.w.tOff == s.w.wOff && s.w.noMore {
			break
		}

		// If available, we claim multiple jobs to do at once, to
		// reduce the contention on the mutex, but no more than batchSize.
		offset := s.w.tOff
		s.w.tOff = (s.w.tOff + 1) % len(s.w.ring)
		count := 1
		for s.w.tOff != s.w.wOff && count < batchSize {
			count++
			s.w.tOff = (s.w.tOff + 1) % len(s.w.ring)
		}

		s.w.mux.Unlock()

		for i := 0; i < count; i++ {
			switch s.lanes {
			case 4:
				computeX4(
					s.w.ring[(offset+i)%len(s.w.ring)].data,
					s.w.ring[(offset+i)%len(s.w.ring)].hashes,
				)
			default:
				computeX2(
					s.w.ring[(offset+i)%len(s.w.ring)].data,
					s.w.ring[(offset+i)%len(s.w.ring)].hashes,
				)
			}
		}

		s.w.mux.Lock()
		for i := 0; i < count; i++ {
			s.w.ring[(offset+i)%len(s.w.ring)].done = true
		}

		// If there isn't another worker thread writing to the stalk already,
		// check whether we can write some hashes to the stalk.
		if !s.w.hashing {
			processed := 0
			s.w.hashing = true

			for {
				hashOffset := s.w.rOff
				hashCount := 0

				// Figure out how many we can hash all at once, so we don't
				// need to require mutex again and again.
				for {
					next := (hashOffset + hashCount) % len(s.w.ring)
					if next == s.w.wOff {
						break
					}
					if !s.w.ring[next].done {
						break
					}
					hashCount++
				}

				if hashCount == 0 {
					break
				}

				s.w.mux.Unlock()

				for i := 0; i < hashCount; i++ {
					_, _ = s.stalk.Write(s.w.ring[(hashOffset+i)%len(s.w.ring)].hashes)
				}

				s.w.mux.Lock()

				if hashOffset != s.w.rOff {
					panic("shouldn't happen")
				}

				for i := 0; i < hashCount; i++ {
					s.w.ring[(hashOffset+i)%len(s.w.ring)].done = false
				}

				s.chunk += uint(s.lanes) * uint(hashCount)
				s.w.rOff = (hashCount + s.w.rOff) % len(s.w.ring)
				processed += hashCount
			}

			s.w.hashing = false

			if s.w.writeSlotWaiting > 0 && processed > 0 {
				s.w.writeSlotCond.Broadcast()
			}
		}
	}
	s.w.mux.Unlock()

	s.w.wg.Done()
}

func (s *State) Reset() {
	if s.w != nil {
		s.w.mux.Lock()
		s.w.noMore = true
		s.w.taskCond.Broadcast()
		s.w.mux.Unlock()
		s.w.wg.Wait()
		s.w = nil
	}

	s.initialTodo = chunkSize
	s.stalk.Reset()
	s.stalk.SwitchDS(0x07)
	s.buf = nil
	s.offset = 0
	s.chunk = 0
}

// Clone create a copy of the current state.
//
// Not supported in multithreaded mode (viz. when using the WithWorkers option).
func (s *State) Clone() State {
	if s.w != nil {
		// TODO Do we want to implement this?
		panic("Clone not supported with parallel workers")
	}

	stalk := s.stalk.Clone().(*sha3.State)
	ret := State{
		initialTodo: s.initialTodo,
		stalk:       *stalk,
		context:     s.context,
		offset:      s.offset,
		chunk:       s.chunk,
		lanes:       s.lanes,
	}

	if s.leaf != nil {
		ret.leaf = s.leaf.Clone().(*sha3.State)
	}

	if s.buf != nil {
		ret.buf = make([]byte, len(s.buf))
		copy(ret.buf, s.buf)
	}

	return ret
}

func Draft10Sum(hash []byte, msg []byte, opts ...Option) {
	// TODO Tweak number of lanes/workers depending on the length of the message
	s := NewDraft10(opts...)
	_, _ = s.Write(msg)
	_, _ = s.Read(hash)
}

// NextWriteSize suggests an favorable size for the buffer passed to the next
// call to Write().
func (s *State) NextWriteSize() int {
	if s.initialTodo != 0 {
		return s.initialTodo
	}

	if s.offset != 0 {
		return len(s.buf) - s.offset
	}

	return s.maxWriteSize
}

// MaxWriteSize is the largest value that will be returned from NextWriteSize().
//
// This can be used to determine the size for a buffer which will be
// fed into Write().
func (s *State) MaxWriteSize() int {
	return s.maxWriteSize
}

// Write feeds more data to the hash.
//
// For optimal performance, use NextWriteSize() to determine optimal size
// for the buffer to prevent copying.
//
// Write() is not threadsafe.
func (s *State) Write(p []byte) (int, error) {
	written := len(p)

	// The first chunk is written directly to the stalk.
	if s.initialTodo > 0 {
		taken := s.initialTodo
		if len(p) < taken {
			taken = len(p)
		}
		headP := p[:taken]
		_, _ = s.stalk.Write(headP)
		s.initialTodo -= taken
		p = p[taken:]
	}

	if len(p) == 0 {
		return written, nil
	}

	// If this is the first bit of data written after the initial chunk,
	// we're out of the fast-path and allocate some buffers.
	if s.buf == nil {
		if s.lanes != 1 {
			s.buf = make([]byte, int(s.lanes)*chunkSize)
		} else {
			// We create the buffer to signal we're past the first chunk,
			// but do not use it.
			s.buf = make([]byte, 0)
			h := sha3.NewTurboShake128(0x0B)
			s.leaf = &h
		}
		_, _ = s.stalk.Write([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		s.stalk.SwitchDS(0x06)

		// Kick of workers, if in multi-threaded mode.
		if s.workers != 1 && s.lanes != 1 {
			s.w = &workersState{
				ring: make([]job, 64*s.workers),
			}
			s.w.writeSlotCond = sync.NewCond(&s.w.mux)
			s.w.taskCond = sync.NewCond(&s.w.mux)

			// TODO Check if it's better to use one single buffer. That reduces
			// the number of allocations, but increases the false sharing if
			// not done carefully.
			for i := 0; i < len(s.w.ring); i++ {
				s.w.ring[i].hashes = make([]byte, 32*int(s.lanes))
				s.w.ring[i].data = make([]byte, int(s.lanes)*chunkSize)
			}

			s.w.wg.Add(s.workers)
			for i := 0; i < s.workers; i++ {
				go s.worker()
			}
		}
	}

	// If we're just using one lane, we don't need to cache in a buffer
	// for parallel hashing. Instead, we feed directly to TurboSHAKE.
	if s.lanes == 1 {
		for len(p) > 0 {
			// Write to current leaf.
			to := chunkSize - s.offset
			if len(p) < to {
				to = len(p)
			}
			_, _ = s.leaf.Write(p[:to])
			p = p[to:]
			s.offset += to

			// Did we fill the chunk?
			if s.offset == chunkSize {
				var cv [32]byte
				_, _ = s.leaf.Read(cv[:])
				_, _ = s.stalk.Write(cv[:])
				s.leaf.Reset()
				s.offset = 0
				s.chunk++
			}
		}

		return written, nil
	}

	// If we can't fill all our lanes or the buffer isn't empty, we write the
	// data to the buffer.
	if s.offset != 0 || len(p) < len(s.buf) {
		to := len(s.buf) - s.offset
		if len(p) < to {
			to = len(p)
		}
		p2 := p[:to]
		p = p[to:]
		copy(s.buf[s.offset:], p2)
		s.offset += to
	}

	// Absorb the buffer if we filled it
	if s.offset == len(s.buf) {
		s.writeX(s.buf)
		s.offset = 0
	}

	// Note that at this point we may assume that s.offset = 0 if len(p) != 0
	if len(p) != 0 && s.offset != 0 {
		panic("shouldn't happen")
	}

	// Absorb a bunch of chunks at the same time.
	if len(p) >= int(s.lanes)*chunkSize {
		p = s.writeX(p)
	}

	// Put the remainder in the buffer.
	if len(p) > 0 {
		copy(s.buf, p)
		s.offset = len(p)
	}

	return written, nil
}

// Absorb a multiple of a multiple of lanes * chunkSize.
// Returns the remainder.
func (s *State) writeX(p []byte) []byte {
	if s.w != nil {
		taskSize := int(s.lanes) * chunkSize
		s.w.mux.Lock()
		for len(p) >= taskSize {
			maxCount := len(p) / taskSize

			// Find number of free slots
			count := 0
			offset := s.w.wOff
			for (offset+count+1)%len(s.w.ring) != s.w.rOff && count < maxCount {
				if s.w.ring[(offset+count)%len(s.w.ring)].done {
					panic("entry shouldn't be done")
				}
				count++
			}

			if count == 0 {
				// Ring is full; need to wait.
				s.w.writeSlotWaiting++
				s.w.writeSlotCond.Wait()
				s.w.writeSlotWaiting--
				continue
			}
			s.w.mux.Unlock()

			for i := 0; i < count; i++ {
				copy(s.w.ring[(offset+i)%len(s.w.ring)].data, p[:taskSize])
				p = p[taskSize:]
			}

			s.w.mux.Lock()
			if s.w.wOff != offset {
				panic("multiple writers are not allowed")
			}
			s.w.wOff = (s.w.wOff + count) % len(s.w.ring)
			if s.w.taskWaiting > 0 {
				s.w.taskCond.Broadcast()
			}
		}
		s.w.mux.Unlock()
		return p
	}

	switch s.lanes {
	case 4:
		var buf [4 * 32]byte
		for len(p) >= 4*chunkSize {
			computeX4(p, buf[:])
			_, _ = s.stalk.Write(buf[:])
			p = p[chunkSize*4:]
			s.chunk += 4
		}
	default:
		var buf [2 * 32]byte
		for len(p) >= 2*chunkSize {
			computeX2(p, buf[:])
			_, _ = s.stalk.Write(buf[:])
			p = p[chunkSize*2:]
			s.chunk += 2
		}
	}
	return p
}

func computeX4(p, out []byte) {
	var x4 keccakf1600.StateX4
	a := x4.Initialize(true)

	for offset := 0; offset < 48*168; offset += 168 {
		for i := 0; i < 21; i++ {
			a[i*4] ^= binary.LittleEndian.Uint64(
				p[8*i+offset:],
			)
			a[i*4+1] ^= binary.LittleEndian.Uint64(
				p[chunkSize+8*i+offset:],
			)
			a[i*4+2] ^= binary.LittleEndian.Uint64(
				p[chunkSize*2+8*i+offset:],
			)
			a[i*4+3] ^= binary.LittleEndian.Uint64(
				p[chunkSize*3+8*i+offset:],
			)
		}

		x4.Permute()
	}

	for i := 0; i < 16; i++ {
		a[i*4] ^= binary.LittleEndian.Uint64(
			p[8*i+48*168:],
		)
		a[i*4+1] ^= binary.LittleEndian.Uint64(
			p[chunkSize+8*i+48*168:],
		)
		a[i*4+2] ^= binary.LittleEndian.Uint64(
			p[chunkSize*2+8*i+48*168:],
		)
		a[i*4+3] ^= binary.LittleEndian.Uint64(
			p[chunkSize*3+8*i+48*168:],
		)
	}

	a[16*4] ^= 0x0b
	a[16*4+1] ^= 0x0b
	a[16*4+2] ^= 0x0b
	a[16*4+3] ^= 0x0b
	a[20*4] ^= 0x80 << 56
	a[20*4+1] ^= 0x80 << 56
	a[20*4+2] ^= 0x80 << 56
	a[20*4+3] ^= 0x80 << 56

	x4.Permute()

	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[8*i:], a[4*i])
		binary.LittleEndian.PutUint64(out[32+8*i:], a[4*i+1])
		binary.LittleEndian.PutUint64(out[32*2+8*i:], a[4*i+2])
		binary.LittleEndian.PutUint64(out[32*3+8*i:], a[4*i+3])
	}
}

func computeX2(p, out []byte) {
	// TODO On M2 Pro, 1/3 of the time is spent on this function
	// and LittleEndian.Uint64 excluding the actual permutation.
	// Rewriting in assembler might be worthwhile.
	var x2 keccakf1600.StateX2
	a := x2.Initialize(true)

	for offset := 0; offset < 48*168; offset += 168 {
		for i := 0; i < 21; i++ {
			a[i*2] ^= binary.LittleEndian.Uint64(
				p[8*i+offset:],
			)
			a[i*2+1] ^= binary.LittleEndian.Uint64(
				p[chunkSize+8*i+offset:],
			)
		}

		x2.Permute()
	}

	for i := 0; i < 16; i++ {
		a[i*2] ^= binary.LittleEndian.Uint64(
			p[8*i+48*168:],
		)
		a[i*2+1] ^= binary.LittleEndian.Uint64(
			p[chunkSize+8*i+48*168:],
		)
	}

	a[16*2] ^= 0x0b
	a[16*2+1] ^= 0x0b
	a[20*2] ^= 0x80 << 56
	a[20*2+1] ^= 0x80 << 56

	x2.Permute()

	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[8*i:], a[2*i])
		binary.LittleEndian.PutUint64(out[32+8*i:], a[2*i+1])
	}
}

func (s *State) Read(p []byte) (int, error) {
	if s.stalk.IsAbsorbing() {
		// Write context string C
		_, _ = s.Write(s.context)

		// Write length_encode( |C| )
		var buf [9]byte
		binary.BigEndian.PutUint64(buf[:8], uint64(len(s.context)))

		// Find first non-zero digit in big endian encoding of context length
		i := 0
		for buf[i] == 0 && i < 8 {
			i++
		}

		buf[8] = byte(8 - i) // number of bytes to represent |C|
		_, _ = s.Write(buf[i:])

		// If we're using parallel workers, mark that we're not writing anymore
		// and wait for the jobs to complete.
		if s.w != nil {
			s.w.mux.Lock()
			s.w.noMore = true
			s.w.taskCond.Broadcast()
			s.w.mux.Unlock()
			s.w.wg.Wait()
			s.w = nil
		}

		// We need to write the chunk number if we're past the first chunk.
		if s.buf != nil {
			// Write last remaining chunk(s)
			var cv [32]byte
			if s.lanes == 1 {
				if s.offset != 0 {
					_, _ = s.leaf.Read(cv[:])
					_, _ = s.stalk.Write(cv[:])
					s.chunk++
				}
			} else {
				remainingBuf := s.buf[:s.offset]
				for len(remainingBuf) > 0 {
					h := sha3.NewTurboShake128(0x0B)
					to := chunkSize
					if len(remainingBuf) < to {
						to = len(remainingBuf)
					}
					_, _ = h.Write(remainingBuf[:to])
					_, _ = h.Read(cv[:])
					_, _ = s.stalk.Write(cv[:])
					s.chunk++
					remainingBuf = remainingBuf[to:]
				}
			}

			// Write length_encode( chunk )
			binary.BigEndian.PutUint64(buf[:8], uint64(s.chunk))

			// Find first non-zero digit in big endian encoding of number of chunks
			i = 0
			for buf[i] == 0 && i < 8 {
				i++
			}

			buf[8] = byte(8 - i) // number of bytes to represent number of chunks.
			_, _ = s.stalk.Write(buf[i:])
			_, _ = s.stalk.Write([]byte{0xff, 0xff})
		}
		s.buf = nil
	}

	return s.stalk.Read(p)
}
