package fi

type PC uint64

type Transition struct {
	// The transition between two instructions.
	// If the value is "0" then it is the same as any.
	source, destination PC
}

func NewTransition(source, destination PC) Transition {
	return Transition{
		source,
		destination,
	}
}