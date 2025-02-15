package arm

import (
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/obj"
)

var _ fi.LinearSearcher[fi.ISTarget] = (*ISLinearSearch)(nil)

type ISLinearSearch struct {}

func NewISLinearSearch() ISLinearSearch {
	return ISLinearSearch{}
}

func (searcher ISLinearSearch) Instructions(instructions []obj.Instruction) (targets []fi.ISTarget) {
	for _, instruction := range instructions {
		target := fi.NewISTarget(fi.PC(instruction.Offset()))
		targets = append(targets, target)
	}

	return
}