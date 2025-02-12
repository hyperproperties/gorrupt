package tester

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"reflect"

	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/quick"
)

type Runner[In, Out any] struct {
	// The path the qemu binary to run the fault injections.
	qemu string
	// The build environment.
	environment []string
	// The required import for the generation.
	imp string
	// The package from which the input/outpus are accessed.
	pkg string
}

func NewRunner[In, Out any](qemu string, imp, pkg string, environment ...string) Runner[In, Out] {
	return Runner[In, Out]{
		qemu: qemu,
		environment: environment,
		imp: imp,
		pkg: pkg,
	}
}

// Generates the main which calls the function under attack.
// The main function (entry point) handles un-/marshalling of the inputs and outputs.
// The input is marshalled with json into a byte slice which is directly inserted into the generated main.
func (runner Runner[In, Out]) Generate(context context.Context, dir string, input In) (string, error) {
	name := quick.String(32, quick.USAlphabet...) + "-main.go"
	filepath := path.Join(dir, name)

	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	defer file.Close()

	bytes, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	inputName := reflect.TypeOf(input).Name()

	main := fmt.Sprintf(`package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"%s"
)

func main() {
	var input %s.%s
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
`, runner.imp, runner.pkg, inputName, bytes)

	if _, err := file.WriteString(main); err != nil {
		return "", err
	}

	return filepath, nil
}

// Creates the attack file (configuration) for qemu.
func (runner Runner[In, Out]) Configure(context context.Context, dir string, plan fi.AttackPlan) (string, error) {
	name := quick.String(32, quick.USAlphabet...) + "-fi"
	filepath := path.Join(dir, name)

	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	for _, attack := range plan {
		attack.WriteAttack(file)
	}

	return filepath, nil
}

// Writes the objdump from the build.
func (runner Runner[In, Out]) Dump(context context.Context, dir, binary string) (string, error) {
	name := quick.String(32, quick.USAlphabet...) + "-objdump"
	filepath := path.Join(dir, name)

	command := exec.CommandContext(context, "sh", "-c", "go tool objdump " + binary + " > " + filepath)
	if err := command.Run(); err != nil {
		return "", err
	}

	return filepath, nil
}

// Builds the generated main (entry point) which produces the binary to execute.
func (runner Runner[In, Out]) Build(context context.Context, dir, main string) (string, error) {
	name := quick.String(32, quick.USAlphabet...) + "-binary"
	filepath := path.Join(dir, name)

	command := exec.CommandContext(context, "go", "build", "-o", filepath, main)
	command.Env = append(os.Environ(), runner.environment...)
	if err := command.Run(); err != nil {
		return "", err
	}

	return filepath, nil
}

// Runs the generated entry-point for the binary which is under attack.
// Before executing the entry-point must be generated and build.
func (runner Runner[In, Out]) QEMU(context context.Context, binary, attack string) (Out, error) {
	command := exec.CommandContext(context, "sh", "-c", runner.qemu + " -fi " + attack + " " + binary)

	output, err := command.CombinedOutput()
	if err != nil {
		var zero Out
		return zero, err
	}

	bytes, err := base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		var zero Out
		return zero, err
	}

	var result Out
	if err := json.Unmarshal(bytes, &result); err != nil {
		var zero Out
		return zero, err
	}

	return result, nil
}

func (runner Runner[In, Out]) Go(context context.Context, main string) (Out, error) {
	command := exec.CommandContext(context, "go", "run", main)

	output, err := command.CombinedOutput()
	if err != nil {
		var zero Out
		return zero, err
	}

	bytes, err := base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		var zero Out
		return zero, err
	}

	var result Out
	if err := json.Unmarshal(bytes, &result); err != nil {
		var zero Out
		return zero, err
	}

	return result, nil
}
