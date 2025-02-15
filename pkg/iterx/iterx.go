package iterx

import "iter"

func Forward[S ~[]E, E any](slice S) iter.Seq[E] {
	return func(yield func(E) bool) {
		for _, element := range slice {
			if !yield(element) {
				break
			}
		}
	}
}

func Once2[E any](element E) iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {
		yield(0, element)
	}
}

func None2[E any]() iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {}
}

func All[E any](seq iter.Seq[E], predicate func(element E) bool) bool {
	for element := range seq {
		if !predicate(element) {
			return false
		}
	}
	return true
}

func Any[E any](seq iter.Seq[E], predicate func(element E) bool) bool {
	for element := range seq {
		if predicate(element) {
			return true
		}
	}
	return false
}

func Backward[S ~[]E, E any](slice S) iter.Seq[E] {
	return func(yield func(E) bool) {
		for idx := len(slice) - 1; idx >= 0; idx-- {
			if !yield(slice[idx]) {
				break
			}
		}
	}
}

func Keys[K, V any](iterator iter.Seq2[K, V]) iter.Seq[K] {
	return func(yield func(K) bool) {
		for k := range iterator {
			if !yield(k) {
				return
			}
		}
	}
}

func Values[K, V any](iterator iter.Seq2[K, V]) iter.Seq[V] {
	return func(yield func(V) bool) {
		for _, v := range iterator {
			if !yield(v) {
				return
			}
		}
	}
}

func Permutations(sub, slice int) iter.Seq[[]int] {
	if sub < 0 {
		panic("permutations of negative length subslices")
	}

	if sub == 0 || slice == 0 {
		return func(yield func([]int) bool) {}
	}

	return func(yield func([]int) bool) {
		counters := make([]int, sub)
		for {
			permutations := make([]int, sub)
			copy(permutations, counters)
			if !yield(permutations) {
				return
			}

			// Find the leftmost element that can still be incremented.
			i := sub - 1
			for i >= 0 && counters[i] == slice-1 {
				i--
			}

			if i < 0 {
				break
			}

			counters[i]++

			// Reset all elements to the right of i to zero.
			for j := i + 1; j < sub; j++ {
				counters[j] = 0
			}
		}
	}
}

func IncrementalPermutations(sub, slice, added int) iter.Seq[[]int] {
	if added == 0 {
		return func(yield func([]int) bool) {}
	}

	if slice == added {
		return Permutations(sub, added)
	}

	return func(yield func([]int) bool) {
		// Idea: Permutations of added with "0" as a marker for when to insert the existing set.
		// Underlying: Permutation of added elements.
		// Overlying: Permutations of existing elements.
		for underlying := range Permutations(sub, added+1) {
			zeros := 0
			for idx := range underlying {
				if underlying[idx] == 0 {
					zeros++
				}
			}

			// All elements should be "not"-added elements
			// since we only consider situations where there
			// is atleast one new then this is skipped.
			if zeros == sub {
				continue
			}

			// The slice if full of added elements.
			permutation := make([]int, sub)
			copy(permutation, underlying)
			if zeros == 0 {
				for idx := range underlying {
					permutation[idx] = underlying[idx] + slice - 1
				}

				if !yield(permutation) {
					return
				}
			}

			// Replace all "0" with an existing (not added) element.
			for overlying := range Permutations(zeros, slice) {
				permutation := make([]int, sub)

				j := 0
				for idx := range permutation {
					if underlying[idx] == 0 {
						permutation[idx] = overlying[j]
						j++
					} else {
						permutation[idx] = underlying[idx] + slice - 1
					}
				}

				if !yield(permutation) {
					return
				}
			}
		}
	}
}

func Map[T any](mapping []T, iterator iter.Seq[[]int]) iter.Seq[[]T] {
	return func(yield func([]T) bool) {
		for indices := range iterator {
			mapped := make([]T, len(indices))
			for idx := range mapped {
				mapped[idx] = mapping[indices[idx]]
			}

			if !yield(mapped) {
				return
			}
		}
	}
}

func CollectN[T any](iterator iter.Seq[T], n int) (slice []T) {
	for element := range iterator {
		if n == 0 {
			break
		}
		slice = append(slice, element)
		n--
	}
	return
}

func Collect[T any](iterator iter.Seq[T]) (slice []T) {
	for element := range iterator {
		slice = append(slice, element)
	}
	return
}

func CollectMap[T comparable, U any](iterator iter.Seq2[T, U]) map[T]U {
	mapping := map[T]U{}
	for key, value := range iterator {
		mapping[key] = value
	}
	return mapping
}

func BufferedPull[T any](seq iter.Seq[T]) (
	next func() (T, bool),
	peek func(lookahead int) (T, bool),
	stop func(),
) {
	iNext, iStop := iter.Pull(seq)

	var buffer []T

	next = func() (T, bool) {
		if len(buffer) > 0 {
			element := buffer[0]
			if len(buffer) > 1 {
				buffer = buffer[1:]
			} else {
				buffer = nil
			}
			return element, true
		}

		return iNext()
	}

	peek = func(lookahead int) (T, bool) {
		if len(buffer) > lookahead-1 {
			return buffer[lookahead-1], true
		}

		for idx := len(buffer); idx < lookahead; idx++ {
			current, ok := iNext()
			if ok {
				buffer = append(buffer, current)
			} else {
				var zero T
				return zero, false
			}
		}

		return buffer[lookahead-1], true
	}

	stop = func() {
		buffer = nil
		iStop()
	}

	return
}

func Pipe[T any](iterator iter.Seq[T], yield func(T) bool) bool {
	for element := range iterator {
		if !yield(element) {
			return false
		}
	}
	return true
}
