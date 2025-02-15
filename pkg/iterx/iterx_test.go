package iterx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPermutations(t *testing.T) {
	// Number of permutations=slice^sub
	tests := []struct {
		description  string
		sub, slice   int
		permutations int
	}{
		{
			description:  "",
			sub:          1,
			slice:        1,
			permutations: 1,
		},
		{
			description:  "",
			sub:          2,
			slice:        3,
			permutations: 9,
		},
		{
			description:  "",
			sub:          2,
			slice:        1,
			permutations: 1,
		},
		{
			description:  "",
			sub:          2,
			slice:        2,
			permutations: 4,
		},
		{
			description:  "",
			sub:          3,
			slice:        2,
			permutations: 8,
		},
		{
			description:  "",
			sub:          3,
			slice:        3,
			permutations: 27,
		},
		{
			description:  "",
			sub:          3,
			slice:        13,
			permutations: 13 * 13 * 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			iterator := Permutations(tt.sub, tt.slice)
			permutations := Collect(iterator)
			assert.Len(t, permutations, tt.permutations)
			for idx, permutation := range permutations {
				assert.NotContains(t, permutations[idx+1:], permutation)
			}
		})
	}
}

func TestIncrementalPermutations(t *testing.T) {
	tests := []struct {
		description       string
		sub, slice, added int
		permutations      int
	}{
		{
			description:  "",
			sub:          1,
			slice:        1,
			added:        0,
			permutations: 0,
		},
		{
			description:  "",
			sub:          1,
			slice:        1,
			added:        1,
			permutations: 1,
		},
		{
			description:  "",
			sub:          1,
			slice:        1,
			added:        2,
			permutations: 2,
		},
		{
			description:  "",
			sub:          3,
			slice:        1,
			added:        1,
			permutations: 7,
		},
		{
			description:  "",
			sub:          4,
			slice:        1,
			added:        5,
			permutations: 1295,
		},
		{
			description:  "",
			sub:          3,
			slice:        2,
			added:        2,
			permutations: 56,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			iterator := IncrementalPermutations(tt.sub, tt.slice, tt.added)
			permutations := Collect(iterator)
			assert.Len(t, permutations, tt.permutations)
			for idx, permutation := range permutations {
				assert.NotContains(t, permutations[idx+1:], permutation, "all elements must be unique")
			}
			for permutation := range Permutations(tt.sub, tt.slice) {
				assert.NotContains(t, permutations, permutation, "must not contain any permutations of the slice only")
			}
			for permutation := range Permutations(tt.sub, tt.added) {
				for idx := range permutation {
					permutation[idx] += tt.slice
				}
				assert.Contains(t, permutations, permutation, "must have all permutations of the added")
			}
		})
	}
}

func TestMapPermutation(t *testing.T) {
	tests := []struct {
		description string
		mapping     []string
	}{
		{
			description: "",
			mapping:     []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			iterator := Map(tt.mapping, Permutations(2, len(tt.mapping)))
			collection := Collect(iterator)
			assert.NotNil(t, collection)
		})
	}
}

func TestMapIncrementalPermutation(t *testing.T) {
	tests := []struct {
		description string
		added       int
		mapping     []string
	}{
		{
			description: "",
			added:       2,
			mapping:     []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			iterator := Map(tt.mapping, IncrementalPermutations(2, len(tt.mapping)-tt.added, tt.added))
			collection := Collect(iterator)
			assert.NotNil(t, collection)
		})
	}
}

func TestBufferedPull(t *testing.T) {
	numbers := []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	next, peek, _ := BufferedPull(Forward(numbers))

	for idx := 0; idx < len(numbers); idx++ {
		element, exists := peek(idx + 1)
		assert.Equal(t, numbers[idx], element)
		assert.True(t, exists)
	}

	element, exists := next()
	assert.Equal(t, numbers[0], element)
	assert.True(t, exists)

	element, exists = next()
	assert.Equal(t, numbers[1], element)
	assert.True(t, exists)

	for idx := 0; idx < len(numbers)-2; idx++ {
		element, exists := peek(idx + 1)
		assert.Equal(t, numbers[idx+2], element)
		assert.True(t, exists)
	}

	_, exists = peek(len(numbers) + 1)
	assert.False(t, exists)
}
