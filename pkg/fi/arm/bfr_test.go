package arm

import (
	"testing"

	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/obj"
	"github.com/stretchr/testify/assert"
)

func TestBFRSearcher(t *testing.T) {
	tests := []struct {
		description  string
		instructions []obj.Instruction
		bfrs         []fi.BFRTarget
		length       int
	}{
		{
			description:  "no instructions",
			instructions: []obj.Instruction{},
			bfrs:         nil,
			length:       0,
		},
		{
			description: "no instructions",
			instructions: []obj.Instruction{
				obj.NewInstruction("abi.go:58", 0x1106c, 0xe59f0038, "MOVW 0x38(R15), R0"),
			},
			bfrs: []fi.BFRTarget{
				fi.NewBFRTarget(fi.NewTransition(0x1106c, 0x1106c+4), 0),
			},
			length: 1,
		},
		{
			description: "no instructions",
			instructions: []obj.Instruction{
				obj.NewInstruction("abi.go:58", 0x11078, 0xe58d0008, "MOVW R0, 0x8(R13)"),
			},
			bfrs: []fi.BFRTarget{
				fi.NewBFRTarget(fi.NewTransition(0x11078-4, 0x11078), 0),
			},
			length: 1,
		},
		{
			description: "no instructions",
			instructions: []obj.Instruction{
				obj.NewInstruction("abi.go:58", 0x11078, 0xe58d0008, "MOVW R3, R4"),
			},
			bfrs: []fi.BFRTarget{
				fi.NewBFRTarget(fi.NewTransition(0x11078-4, 0x11078), 3),
				fi.NewBFRTarget(fi.NewTransition(0x11078, 0x11078+4), 4),
			},
			length: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			searcher := NewBFRSearcher()
			bfrs := searcher.Instructions(tt.instructions)
			assert.Len(t, bfrs, tt.length)
			assert.ElementsMatch(t, tt.bfrs, bfrs)
		})
	}
}
