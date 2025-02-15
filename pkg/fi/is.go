package fi

import "fmt"

var _ Target = (*ISTarget)(nil)

type ISTarget struct {
	pc PC
}

func NewISTarget(pc PC) ISTarget {
	return ISTarget{ pc }
}

func (target ISTarget) Visit(visitor TagetVisitor) {
	visitor.IS(target)
}

var _ Attack = (*IS)(nil)

type IS struct {
	ISTarget
	counter int32
}

func NewIS(pc PC, counter int32) IS {
	return IS{ NewISTarget(pc), counter }
}

func (is IS) String() string {
	return fmt.Sprintf("is %d %d", is.pc, is.counter)
}