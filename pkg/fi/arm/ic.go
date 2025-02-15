package arm

import (
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/obj"
)

var _ fi.LinearSearcher[fi.ICTarget] = (*ICLinearSearch)(nil)

type ICLinearSearch struct {}

func NewICLinearSearch() ICLinearSearch {
	return ICLinearSearch{}
}

func (searcher ICLinearSearch) Instructions(instructions []obj.Instruction) (targets []fi.ICTarget) {
	for _, instruction := range instructions {
		target := fi.NewICTarget(fi.PC(instruction.Offset()))
		targets = append(targets, target)
	}

	return
}