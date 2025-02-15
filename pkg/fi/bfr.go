package fi

import (
	"fmt"

	"github.com/hyperproperties/gorrupt/pkg/obj"
)

var _ Target = (*BFRTarget)(nil)

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

func (target BFRTarget) Visit(visitor TagetVisitor) {
	visitor.BFR(target)
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

func NewBFR(register byte, counter int32, source, destination PC, mask uint32) BFR {
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

func (bfr BFR) Register() byte {
	return bfr.register
}

func (bfr BFR) Counter() int32 {
	return bfr.counter
}

func (bfr BFR) Source() PC {
	return bfr.source
}

func (bfr BFR) Destination() PC {
	return bfr.destination
}

func (bfr BFR) Mask() uint32 {
	return bfr.mask
}

func (bfr BFR) String() string {
	return fmt.Sprintf("bfr %d %d 0x%x 0x%x %d", bfr.register, bfr.counter, bfr.source, bfr.destination, bfr.mask)
}

type BFRSearcher interface {
	Instructions(instructions []obj.Instruction) []BFR
}
