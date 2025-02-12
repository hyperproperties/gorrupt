package pkg

type Calculator struct {
	Offset int
}

//go:noinline
func (calculator Calculator) Addition(a, b int) int {
	return calculator.Offset + a + b
}

type AdditionInput struct {
	Calculator Calculator
	A, B int
}

func (input AdditionInput) Call() AdditionOutput {
	ret0 := input.Calculator.Addition(input.A, input.B)
	return AdditionOutput{
		Ret0: ret0,
	}
}

type AdditionOutput struct {
	Ret0 int
}