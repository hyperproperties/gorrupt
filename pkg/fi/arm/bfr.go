package arm

import (
	"fmt"
	"slices"

	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/obj"
)

type BFRSearcher struct{}

func NewBFRSearcher() BFRSearcher {
	return BFRSearcher{}
}

// Searches for BFR targets in the instructions.
func (searcher BFRSearcher) Instructions(instructions []obj.Instruction) (targets []fi.BFRTarget) {
	for i := range instructions {
		instruction, err := NewInstruction(instructions[i])
		if err != nil {
			fmt.Println(err)
		}

		// Get all registers in instruction in order. The first one is usually the destination.
		registers := instruction.Registers()
		if len(registers) > 0 {
			targets = append(targets, searcher.targetBefore(registers[0], instruction.Offset())...)
			for _, register := range slices.Compact(registers) {
				targets = append(targets, searcher.targetAfter(register, instruction.Offset())...)
			}
		}
	}

	// Removes duplicate targets.
	targets = slices.Compact(targets)

	return
}

func (searcher BFRSearcher) targetBefore(register Register, offset uint64) (targets []fi.BFRTarget) {
	return searcher.target(register, offset-4, offset)
}

func (searcher BFRSearcher) targetAfter(register Register, offset uint64) (targets []fi.BFRTarget) {
	return searcher.target(register, offset, offset+4)
}

// Creates the BFR target if the register has an index and is therefore supported by qemu-fi.
func (searcher BFRSearcher) target(register Register, source, destination uint64) (targets []fi.BFRTarget) {
	if index, err := register.Index(); err == nil {
		transition := fi.NewTransition(source, destination)
		target := fi.NewBFRTarget(transition, index)
		targets = append(targets, target)
	}
	return
}
