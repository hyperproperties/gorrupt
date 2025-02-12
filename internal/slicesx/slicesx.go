package slicesx

import "iter"

func Map[S ~[]E, E, M any](s S, m func(e E) M) iter.Seq[M] {
	return func(yield func(M) bool) {
		for i := 0; i < len(s); i++ {
			if !yield(m(s[i])) {
				return
			}
		}
	}
}
