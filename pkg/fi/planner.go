package fi

import "iter"

var _ TagetVisitor = (*AttackPlanner)(nil)

type AttackPlanner struct {
	attacks []Attack
}

func NewAttackPlanner() AttackPlanner {
	return AttackPlanner{}
}

func (planner *AttackPlanner) Plan(targets ...Target) iter.Seq2[int, AttackPlan] {
	if len(targets) == 0 {
		return func(yield func(int, AttackPlan) bool) {
			yield(0, AttackPlan{})
		}
	}

	planner.attacks = make([]Attack, 0)
	for i := range targets {
		targets[i].Visit(planner)
	}
	
	return func(yield func(int, AttackPlan) bool) {
		i := 0

		for _, attack := range planner.attacks {
			i++
			if !yield(i, AttackPlan{attack}) {
				return
			}
		}
	}
}

func (planner *AttackPlanner) BFR(target BFRTarget) {
	for i := 0; i < 32; i++ {
		bfr := NewBFR(target.register, 0, target.source, target.destination, 1<<i)
		planner.attacks = append(planner.attacks, bfr)
	}
}

func (planner *AttackPlanner) IS(target ISTarget) {
	planner.attacks = append(planner.attacks, NewIS(target.pc, 0))
}

func (planner *AttackPlanner) IC(target ICTarget) {
	for i := 0; i < 32; i++ {
		ic := NewIC(target.pc, 1 << i, 0)
		planner.attacks = append(planner.attacks, ic)
	}
}