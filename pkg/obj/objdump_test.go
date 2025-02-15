package obj

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFunctionName(t *testing.T) {
	tests := []struct {
		str          string
		isIdentifier bool
	}{
		{
			str:          "",
			isIdentifier: false,
		},
		{
			str:          "1",
			isIdentifier: false,
		},
		{
			str:          "_1",
			isIdentifier: false,
		},
		{
			str:          "a1",
			isIdentifier: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			assert.Equal(t, tt.isIdentifier, IsIdentifier(tt.str))
		})
	}
}

func TestParseFunctionline(t *testing.T) {
	tests := []struct {
		line          string
		section       string
		qualifiedName string
		source        string
		pack          string
		receiver      string
		function      string
		isCGO         bool
		isXCGO        bool
	}{
		{
			line:          "",
			section:       "",
			qualifiedName: "",
			source:        "",
			pack:          "",
			function:      "",
			isCGO:         false,
			isXCGO:        false,
		},
		{
			line:          "TEXT _cgo_04fbb8f65a5f_C2func_getaddrinfo(SB) ",
			section:       "TEXT",
			qualifiedName: "_cgo_04fbb8f65a5f_C2func_getaddrinfo(SB)",
			pack:          "",
			source:        "",
			function:      "_cgo_04fbb8f65a5f_C2func_getaddrinfo",
			isCGO:         true,
			isXCGO:        false,
		},
		{
			line:          "TEXT testing.tRunner.func1.2(SB) /usr/local/go/src/testing/testing.go",
			section:       "TEXT",
			qualifiedName: "testing.tRunner.func1.2(SB)",
			source:        "/usr/local/go/src/testing/testing.go",
			pack:          "testing",
			function:      "tRunner.func1",
			isCGO:         false,
			isXCGO:        false,
		},
		{
			line:          "TEXT unique.addUniqueMap[go.shape.struct { net/netip.isV6 bool; net/netip.zoneV6 string }](SB) /usr/local/go/src/unique/handle.go",
			section:       "TEXT",
			qualifiedName: "unique.addUniqueMap[go.shape.struct { net/netip.isV6 bool; net/netip.zoneV6 string }](SB)",
			source:        "/usr/local/go/src/unique/handle.go",
			pack:          "unique",
			function:      "addUniqueMap",
			isCGO:         false,
			isXCGO:        false,
		},
		{
			line:          "TEXT type:.eq.go.shape.struct { net/netip.isV6 bool; net/netip.zoneV6 string }(SB) <autogenerated>",
			section:       "TEXT",
			qualifiedName: "type:.eq.go.shape.struct { net/netip.isV6 bool; net/netip.zoneV6 string }(SB)",
			source:        "<autogenerated>",
			pack:          "",
			function:      "eq",
			isCGO:         false,
			isXCGO:        false,
		},
		{
			line:          "TEXT x_cgo_getstackbound(SB) ",
			section:       "TEXT",
			qualifiedName: "x_cgo_getstackbound(SB)",
			source:        "",
			pack:          "",
			function:      "x_cgo_getstackbound",
			isCGO:         false,
			isXCGO:        true,
		},
		{
			line:          "TEXT main.Calculator.Addition(SB) /home/andreas/git/gorrupt/examples/arithmetic/main.go",
			section:       "TEXT",
			qualifiedName: "main.Calculator.Addition(SB)",
			source:        "/home/andreas/git/gorrupt/examples/arithmetic/main.go",
			pack:          "main",
			receiver:      "Calculator",
			function:      "Addition",
			isCGO:         false,
			isXCGO:        false,
		},
		{
			line:          "TEXT main.(*RPC).Addition(SB) /home/andreas/git/gorrupt/examples/arithmetic/main.go",
			section:       "TEXT",
			qualifiedName: "main.(*RPC).Addition(SB)",
			source:        "/home/andreas/git/gorrupt/examples/arithmetic/main.go",
			pack:          "main",
			function:      "Addition",
			receiver:      "(*RPC)",
			isCGO:         false,
			isXCGO:        false,
		},
		{
			line:          "TEXT github.com/hyperproperties/gorrupt/pkg/objdump.Function.Start(SB) /home/andreas/git/gorrupt/pkg/objdump/objdump.go",
			section:       "TEXT",
			qualifiedName: "github.com/hyperproperties/gorrupt/pkg/objdump.Function.Start(SB)",
			source:        "/home/andreas/git/gorrupt/pkg/objdump/objdump.go",
			pack:          "github.com/hyperproperties/gorrupt/pkg/objdump",
			receiver:      "Function",
			function:      "Start",
			isCGO:         false,
			isXCGO:        false,
		},
		{
			line:          "TEXT github.com/hyperproperties/gorrupt/examples/arithmetic/pkg.Calculator.Addition(SB) /home/andreas/git/gorrupt/examples/arithmetic/pkg/addition.go",
			section:       "TEXT",
			qualifiedName: "github.com/hyperproperties/gorrupt/examples/arithmetic/pkg.Calculator.Addition(SB)",
			source:        "/home/andreas/git/gorrupt/examples/arithmetic/pkg/addition.go",
			pack:          "github.com/hyperproperties/gorrupt/examples/arithmetic/pkg",
			function:      "Addition",
			receiver:      "Calculator",
			isCGO:         false,
			isXCGO:        false,
		},
		{
			line:          "TEXT github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_0/pkg.VerifyPIN(SB) /home/andreas/git/gorrupt/examples/fissc/VerifyPIN_0/pkg/verify_pin.go",
			section:       "TEXT",
			qualifiedName: "github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_0/pkg.VerifyPIN(SB)",
			source:        "/home/andreas/git/gorrupt/examples/fissc/VerifyPIN_0/pkg/verify_pin.go",
			pack:          "github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_0/pkg",
			function:      "VerifyPIN",
			isCGO:         false,
			isXCGO:        false,
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			section, qualifiedName, source := ParseFunctionline(tt.line)
			function := NewFunction(section, qualifiedName, source)
			assert.Equal(t, tt.section, function.Section())
			assert.Equal(t, tt.qualifiedName, function.QualifiedName())
			assert.Equal(t, tt.source, function.Source())
			assert.Equal(t, tt.pack, function.Package())
			assert.Equal(t, tt.receiver, function.Receiver())
			assert.Equal(t, tt.function, function.Function())
			assert.Equal(t, tt.isCGO, function.IsCGO())
			assert.Equal(t, tt.isXCGO, function.IsXCGO())
		})
	}
}

func TestParseInstructionLine(t *testing.T) {
	tests := []struct {
		line     string
		source   string
		offset   uint64
		opcode   uint64
		name     string
		isUnkown bool
	}{
		{
			line:     "",
			source:   "",
			offset:   0,
			opcode:   0,
			name:     "",
			isUnkown: false,
		},
		{
			line:     "  testing.go:1617	0x4ea51a		48898424b0000000	MOVQ AX, 0xb0(SP)				",
			source:   "testing.go:1617",
			offset:   0x4ea51a,
			opcode:   0x48898424b0000000,
			name:     "MOVQ AX, 0xb0(SP)",
			isUnkown: false,
		},
		{
			line:     "  :-1			0x401000		f3			?				",
			source:   ":-1",
			offset:   0x401000,
			opcode:   0xf3,
			name:     "?",
			isUnkown: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			source, offset, opcode, name := ParseInstructionLine(tt.line)
			instruction := NewInstruction(source, offset, opcode, name)
			assert.Equal(t, tt.source, instruction.Source())
			assert.Equal(t, tt.offset, instruction.Offset())
			assert.Equal(t, tt.opcode, instruction.Opcode())
			assert.Equal(t, tt.name, instruction.Name())
			assert.Equal(t, tt.isUnkown, instruction.IsUnkown())
		})
	}
}

func TestSplitN(t *testing.T) {
	tests := []struct {
		str   string
		n     int
		split []string
	}{
		{
			str:   "a   b   c    d e f g",
			n:     4,
			split: []string{"a", "b", "c", "d e f g"},
		},
		{
			str:   "a   b   c    d e f g",
			n:     43,
			split: []string{"a", "b", "c", "d", "e", "f", "g"},
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			split := splitN(tt.str, " ", tt.n)
			assert.ElementsMatch(t, tt.split, split)
		})
	}
}
