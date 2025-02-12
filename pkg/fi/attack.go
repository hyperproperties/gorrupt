package fi

import "io"

type Attack interface {
	WriteAttack(writer io.Writer)
}

type AttackPlan []Attack
