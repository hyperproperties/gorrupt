package fi

import (
	"fmt"
	"strings"

	"github.com/hyperproperties/gorrupt/pkg/obj"
)

type LinearSearcher[T Target] interface {
	Instructions(instructions []obj.Instruction) (targets []T)
}

// This is like the node in when making a programming language.
// The visitor of this node is e.g. one which computes all the targets.
type Target interface {
	Visit(visitor TagetVisitor)
}

type TagetVisitor interface {
	BFR(bfr BFRTarget)
	IS(is ISTarget)
	IC(ic ICTarget)
}

type Attack interface {
	fmt.Stringer
}

type AttackPlan []Attack

func (plan AttackPlan) String() string {
	strs := make([]string, len(plan))
	for i := range plan {
		strs[i] = plan[i].String()
	}
	return "[" + strings.Join(strs, ", ") + "]"
}