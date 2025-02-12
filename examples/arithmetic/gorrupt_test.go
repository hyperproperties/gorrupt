package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hyperproperties/gorrupt/examples/arithmetic/pkg"
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/fi/arm"
	"github.com/hyperproperties/gorrupt/pkg/obj"
)

func GenerateMain(context context.Context, input pkg.AdditionInput) error {
	main, err := os.OpenFile("./main.go", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer main.Close()

	bytes, err := json.Marshal(input)
	if err != nil {
		return err
	}
	
	content := fmt.Sprintf(`package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hyperproperties/gorrupt/examples/arithmetic/pkg"
)

func main() {
	var input pkg.AdditionInput
	if err := json.Unmarshal(%#v, &input); err != nil {
		panic(err)
	}
	output := input.Call()
	bytes, err := json.Marshal(output)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(bytes))
}
`, bytes)

	if _, err := main.WriteString(content); err != nil {
		return err
	}

	build_cmd := exec.CommandContext(context, "go", "build", "-o", "main", "./main.go")
	build_cmd.Env = append(os.Environ(), "GOARCH=arm", "GOOS=linux")
	if err := build_cmd.Run(); err != nil {
		return err
	}

	tool_cmd := exec.CommandContext(context, "sh", "-c", "go tool objdump ./main > ./main.disassembly")
	if err := tool_cmd.Run(); err != nil {
		return err
	}

	return nil
}

func GetDump() (dump obj.Dump, err error) {
	objdumpReader, err := os.Open("./main.disassembly")
	if err != nil {
		return 
	}
	defer objdumpReader.Close()

	dump, err = obj.Parse(objdumpReader)
	if err != nil {
		return
	}

	return
}

func ExecuteUnderAttack(context context.Context, input pkg.AdditionInput, attack fi.Attack) (ret pkg.AdditionOutput, err error) {
	// Write attack to file
	file, err := os.OpenFile("./fi", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	attack.WriteAttack(file)

	// Run under the attack
	cmd := exec.CommandContext(context, "sh", "-c", "../../../qemu-fi/build-arm/qemu-arm -fi ./fi ./main")

	// Get the output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return
	}

	// Decode the base64 output bytes
	decodedBytes, err := base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		return 
	}

	// Unmarshal the result
	err = json.Unmarshal(decodedBytes, &ret)

	return
}

func Execute(context context.Context, input pkg.AdditionInput) (pkg.AdditionOutput, error) {
	return input.Call(), nil
}

func Test(t *testing.T) {
	for i := 0; i < 100; i++ {
		t.Log("Iteration", i)
		Experiment(t)
	}
}

func Experiment(t *testing.T) {
	input := pkg.AdditionInput {
		Calculator: pkg.Calculator{
			Offset: rand.Intn(256),
		},
		A: rand.Intn(256),
		B: rand.Intn(256),
	}

	t.Log("Common input", input)

	experimentContext, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := GenerateMain(experimentContext, input); err != nil {
		return
	}

	dump, err := GetDump()
	if err != nil {
		return
	}

	addition := dump.FunctionInPackageWithReceiver(
		"github.com/hyperproperties/gorrupt/examples/arithmetic/pkg", "Calculator", "Addition",
	)[0]
	targets := arm.NewBFRSearcher().Instructions(addition.Instructions())

	e0, err := Execute(experimentContext, input)
	if err != nil {
		return
	}

	for _, target := range targets {
		for _, attack := range target.Exhaustive(0) {
			var buffer bytes.Buffer
			attack.WriteAttack(&buffer)
			t.Log("attack:", "[" + strings.TrimSpace(buffer.String()) + "]")
			
			executionContext, _ := context.WithTimeout(experimentContext, time.Second)
			e1, err := ExecuteUnderAttack(executionContext, input, attack)
			if err != nil {
				t.Log("Execution under attack failed")
				continue
			}

			if e0.Ret0 != e1.Ret0 {
				t.Error("violation of:", e0.Ret0, "==", e1.Ret0)
			} else {
				t.Error("no violation of:", e0.Ret0, "==", e1.Ret0)
			}
		}
	}
}