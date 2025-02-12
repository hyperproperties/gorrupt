package fi

import (
	"fmt"
	"io"
	"iter"

	"github.com/hyperproperties/gorrupt/pkg/obj"
)

type Transition struct {
	// The transition between two instructions.
	// If the value is "0" then it is the same as any.
	source, destination uint64
}

func NewTransition(source, destination uint64) Transition {
	return Transition{
		source,
		destination,
	}
}

type BFRTarget struct {
	Transition
	// The index of the register to bit-flip.
	register byte
}

func NewBFRTarget(transition Transition, register byte) BFRTarget {
	return BFRTarget{
		transition,
		register,
	}
}

//TODO: This is maybe - actually - the language of the attacks.
func (target BFRTarget) Exhaustive(counter int32) iter.Seq2[int, BFR] {
	return func(yield func(int, BFR) bool) {
		for i := 0; i < 32; i++ {
			bfr := NewBFR(target.register, counter, target.source, target.destination, 1<<i)
			if !yield(i, bfr) {
				return
			}
		}
	}
}

var _ Attack = (*BFR)(nil)

// Bit-Flip Regiser (BFR):
//
//	The fault model for BFR is (reg counter source destination mask)
//	An example is (bit-flip-register 0 1 ae800 0xae7cc 0x01)
type BFR struct {
	BFRTarget
	// The logical counter's initial value.
	counter int32
	// The mask describing what bits to flip.
	mask uint32
}

func NewBFR(register byte, counter int32, source, destination uint64, mask uint32) BFR {
	return BFR{
		BFRTarget{
			Transition{
				source,
				destination,
			},
			register,
		},
		counter,
		mask,
	}
}

func BFRSFromTarget(target BFRTarget) (bfrs []BFR) {
	for counter := 0; counter < 4; counter++ {
		for shift := 0; shift < 32; shift++ {
			bfr := NewBFR(target.register, int32(counter), target.source, target.destination, 1<<shift)
			bfrs = append(bfrs, bfr)
		}
	}

	return
}

func (bfr BFR) Register() byte {
	return bfr.register
}

func (bfr BFR) Counter() int32 {
	return bfr.counter
}

func (bfr BFR) Source() uint64 {
	return bfr.source
}

func (bfr BFR) Destination() uint64 {
	return bfr.destination
}

func (bfr BFR) Mask() uint32 {
	return bfr.mask
}

// FIXME: Should return an error
func (bfr BFR) WriteAttack(writer io.Writer) {
	io.WriteString(writer, "bfr")
	io.WriteString(writer, " ")
	fmt.Fprintf(writer, "%d", bfr.register)
	io.WriteString(writer, " ")
	fmt.Fprintf(writer, "%d", bfr.counter)
	io.WriteString(writer, " ")
	fmt.Fprintf(writer, "0x%x", bfr.source)
	io.WriteString(writer, " ")
	fmt.Fprintf(writer, "0x%x", bfr.destination)
	io.WriteString(writer, " ")
	fmt.Fprintf(writer, "%d", bfr.mask)
	io.WriteString(writer, " ")
}

type BFRSearcher interface {
	Instructions(instructions []obj.Instruction) []BFR
}
