package arm

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/hyperproperties/gorrupt/internal/slicesx"
	"github.com/hyperproperties/gorrupt/pkg/obj"
)

var ErrUnknownInstruction = errors.New("unknown instruction")

type Operation byte

const (
	OP_UNKNOWN = Operation(iota)
	OP_MOV
)

type Register string

const (
	// https://developer.arm.com/documentation/107656/0101/Registers/Registers-in-the-register-bank
	// Registers R0 to R12 are general-purpose registers. The first eight (R0-R7) are also called low registers.
	// Due to the limited number of bits in instruction opcodes, many 16-bit instructions can only access the low
	// registers. The high registers (R8-R12) can be used with 32-bit instructions and with some 16-bit instructions
	// like the MOV instruction. The initial values of R0 to R12 are UNKNOWN out of reset.

	// General-purpose low registers:
	R0 = Register("R0") // Argument register 0
	R1 = Register("R1") // Argument register 1
	R2 = Register("R2") // Argument register 2
	R3 = Register("R3") // Argument register 3
	R4 = Register("R4") // Callee-saved register
	R5 = Register("R5") // Callee-saved register
	R6 = Register("R6") // Callee-saved register
	R7 = Register("R7") // Callee-saved register
	// General-purpose high registers:
	R8  = Register("R8") // Callee-saved register
	R9  = Register("R9") // Callee-saved register
	R10 = Register("R10")
	R11 = Register("R11") // Frame pointer (FP)
	R12 = Register("R12") // Intra-procedural call scratch register (IP)

	R13 = Register("R13") // Banked Main Stack Pointer (MSP) and Process Stack Pointer (PSP).
	// R14 is also called the Link Register (LR). This holds the return address when calling a function or subroutine.
	R14 = Register("R14") // Link register (LR)
	// R15 is the Program Counter (PC). It is readable and writable. A read returns the current instruction
	// address + 4 while writing to a PC (for example using data processing instructions) causes a branch operation.
	R15 = Register("R15") // Program counter (PC)

	// Floating-point registers:
	// Maybe these are the "D" registers (Double precision) which essentially is two "S" (single) registers together.
	// I think this is for 32-bit floating-point computation specifically from the Go objdump output.
	// https://developer.arm.com/documentation/107656/0101/Registers/Floating-point-registers
	// OBS: I am not entirely sure how TCG generation for F (Or D) registers is done.
	F0  = Register("F0")
	F1  = Register("F1")
	F2  = Register("F2")
	F3  = Register("F3")
	F4  = Register("F4")
	F5  = Register("F5")
	F6  = Register("F6")
	F7  = Register("F7")
	F8  = Register("F8")
	F9  = Register("F9")
	F10 = Register("F10")
	F11 = Register("F11")
	F12 = Register("F12")
	F13 = Register("F13")
	F14 = Register("F14")
	F15 = Register("F15")

	// Special-purpose registers
	// Contains various ALU flags which are required for conditional branches and instruction operations that need special flags, for example subtract with carry.
	APSR = Register("APSR") // Application Program Status Register (APSR).
	// Contains current interrupt or exception state information.
	IPSR = Register("IPSR") // Interrupt Program Status Register (IPSR).
	// Contains execution state information.
	EPSR  = Register("EPSR")  // Execution Program Status Register (EPSR)
	FPSCR = Register("FPSCR") // Floating-Point Status and Control Register
)

func (register Register) Index() (byte, error) {
	switch register {
	case R0:
		return 0, nil
	case R1:
		return 1, nil
	case R2:
		return 2, nil
	case R3:
		return 3, nil
	case R4:
		return 4, nil
	case R5:
		return 5, nil
	case R6:
		return 6, nil
	case R7:
		return 7, nil
	case R8:
		return 8, nil
	case R9:
		return 9, nil
	case R10:
		return 10, nil
	case R11:
		return 11, nil
	case R12:
		return 12, nil
	case R13:
		return 13, nil
	case R14:
		return 14, nil
	case R15:
		return 15, nil
	default:
		return 0, errors.New("register does not have an index")
	}
}

type Argument struct {
	value string
}

func NewArgument(value string) Argument {
	return Argument{
		value,
	}
}

func (arg Argument) IsRegister() (Register, bool) {
	switch arg.value {
	case string(R0),
		/* For now F and special registers are not considered:
		string(F0), string(F1), string(F2), string(F3), string(F4), string(F5), string(F6), string(F7), string(F8), string(F9), string(F10), string(F11), string(F12), string(F13), string(F14), string(F15),
		string(APSR), string(IPSR), string(EPSR), string(FPSCR)*/
		string(R1), string(R2), string(R3), string(R4), string(R5), string(R6), string(R7), string(R8),
		string(R9), string(R10), string(R11), string(R12), string(R13), string(R14), string(R15):
		return Register(arg.value), true
	}
	return Register(""), false
}

func (arg Argument) Registers() (registers []Register) {
	regex := regexp.MustCompile(`R\d+`)
	identifiers := regex.FindAllString(arg.value, -1)
	for _, identifier := range identifiers {
		switch register := Register(identifier); register {
		case R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15:
			registers = append(registers, register)
		}
	}

	return
}

type Instruction struct {
	obj.Instruction
	operation string
	arguments []Argument
}

func NewInstruction(instruction obj.Instruction) (Instruction, error) {
	firstSpace := strings.Index(instruction.Name(), " ")
	if firstSpace == -1 {
		var zero Instruction
		return zero, ErrUnknownInstruction
	}

	fields := strings.Fields(strings.Replace(instruction.Name()[firstSpace:], ",", "", -1))
	mapped_fields := slicesx.Map(
		fields,
		func(str string) Argument { return NewArgument(str) },
	)
	arguments := slices.Collect(mapped_fields)
	operation := instruction.Name()[:firstSpace]

	return Instruction{
		Instruction: instruction,
		operation:   operation,
		arguments:   arguments,
	}, nil
}

func (instruction Instruction) Registers() (registers []Register) {
	for _, argument := range instruction.arguments {
		registers = append(registers, argument.Registers()...)
	}

	return
}

func (instruction Instruction) IsMOV() bool {
	return strings.HasPrefix(instruction.operation, "MOV")
}

func (instruction Instruction) IsADD() bool {
	return strings.HasPrefix(instruction.operation, "ADD")
}

func (instruction Instruction) IsSUB() bool {
	return strings.HasPrefix(instruction.operation, "SUB")
}
