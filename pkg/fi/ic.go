package fi

import "fmt"

var _ Target = (*ICTarget)(nil)

type ICTarget struct {
	pc PC
}

func NewICTarget(pc PC) ICTarget {
	return ICTarget{ pc }
}

func (target ICTarget) Visit(visitor TagetVisitor) {
	visitor.IC(target)
}

var _ Attack = (*IC)(nil)

type IC struct {
	ICTarget
	mask uint32
	counter int32
}

func NewIC(pc PC, mask uint32, counter int32) IC {
	return IC{ NewICTarget(pc), mask, counter }
}

func (ic IC) String() string {
	return fmt.Sprintf("ic %d %d %d", ic.pc, ic.mask, ic.counter)
}