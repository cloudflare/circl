// Package cursor aids with iteration of slices.
package cursor

type Cursor[V ~[]E, E any] []E

func New[V ~[]E, E any](x V) Cursor[V, E] { return Cursor[V, E](x) }

// Next return an slice of size n and advances the pointer.
func (s *Cursor[V, E]) Next(n uint) (out V) {
	if uint(len(*s)) >= n {
		out = V(*s)[:n]
		*s = (*s)[n:]
	}
	return
}
