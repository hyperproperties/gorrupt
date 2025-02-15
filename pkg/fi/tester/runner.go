package tester

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"os/exec"
	"path"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/hyperproperties/gorrupt/pkg/execx"
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/obj"
)

type Runner[In, Out any] struct {
	counter atomic.Uint64

	// The path the qemu binary to run the fault injections.
	qemu string
	// The build environment.
	environment []string
	// The required import for the generation.
	imp string
	// The package from which the input/outpus are accessed.
	pkg string
}

func NewRunner[In, Out any](qemu string, imp, pkg string, environment ...string) *Runner[In, Out] {
	return &Runner[In, Out]{
		qemu:        qemu,
		environment: environment,
		imp:         imp,
		pkg:         pkg,
	}
}

func (runner *Runner[In, Out]) uniqueString() string {
	value := runner.counter.Add(1)
	return fmt.Sprintf("%v", value)
}

// Generates the main which calls the function under attack.
// The main function (entry point) handles un-/marshalling of the inputs and outputs.
// The input is marshalled with json into a byte slice which is directly inserted into the generated main.
func (runner *Runner[In, Out]) Generate(context context.Context, dir string, input In) (string, error) {
	name := runner.uniqueString() + "-main.go"
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
func (runner *Runner[In, Out]) Configure(context context.Context, dir string, plan fi.AttackPlan) (string, error) {
	name := runner.uniqueString() + "-fi"
	filepath := path.Join(dir, name)

	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	defer file.Close()

	for _, attack := range plan {
		io.WriteString(file, attack.String()+"\n")
	}

	return filepath, nil
}

// Writes the objdump from the build.
func (runner *Runner[In, Out]) Dump(context context.Context, dir, binary string) (string, error) {
	name := runner.uniqueString() + "-objdump"
	filepath := path.Join(dir, name)

	command := exec.CommandContext(context, "sh", "-c", "go tool objdump "+binary+" > "+filepath)
	if err := command.Run(); err != nil {
		return "", err
	}

	return filepath, nil
}

// Builds the generated main (entry point) which produces the binary to execute.
func (runner *Runner[In, Out]) Build(context context.Context, dir, main string) (string, error) {
	name := runner.uniqueString() + "-binary"
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
func (runner *Runner[In, Out]) QEMU(ctx context.Context, binary, attack string) (Out, error) {
	var output []byte
	err := execx.RunCommandContext(ctx, func(command *exec.Cmd) (err error) {
		output, err = command.CombinedOutput()
		return err
	}, "sh", "-c", runner.qemu+" -fi "+attack+" "+binary+" -no-shutdown -no-reboot")

	if err != nil {
		var configuration Out
		return configuration, err
	}

	bytes, err := base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		var configuration Out
		return configuration, err
	}

	var result Out
	if err := json.Unmarshal(bytes, &result); err != nil {
		var configuration Out
		return configuration, err
	}

	return result, nil
}

func (runner *Runner[In, Out]) Go(context context.Context, main string) (Out, error) {
	command := exec.CommandContext(context, "go", "run", main)

	output, err := command.CombinedOutput()
	if err != nil {
		var configuration Out
		return configuration, err
	}

	bytes, err := base64.StdEncoding.DecodeString(string(output))
	if err != nil {
		var configuration Out
		return configuration, err
	}

	var result Out
	if err := json.Unmarshal(bytes, &result); err != nil {
		var configuration Out
		return configuration, err
	}

	return result, nil
}

type QuantifierOption func(configuration *QuantifierConfiguration)

func WithTargetOptions(options ...TargetsOption) QuantifierOption {
	return func(configuration *QuantifierConfiguration) {
		configuration.targets = append(configuration.targets, options...)
	}
}

func WithDirectory(directory string) QuantifierOption {
	return func(configuration *QuantifierConfiguration) {
		configuration.directory = directory
	}
}

func WithTimeout(timeout time.Duration) QuantifierOption {
	return func(configuration *QuantifierConfiguration) {
		configuration.timeout = timeout
	}
}

type QuantifierConfiguration struct {
	directory string
	main      string
	binary    string
	landfill  string
	dump      *obj.Dump
	targets   []TargetsOption
	timeout   time.Duration
}

func NewQuantifierConfiguration(options ...QuantifierOption) QuantifierConfiguration {
	var configuration QuantifierConfiguration
	for idx := range options {
		options[idx](&configuration)
	}
	return configuration
}

func (configuration QuantifierConfiguration) Parallel(options ...ParallelQuantifierOption) ParallelQuantifierConfiguration {
	return NewParallelQuantifierConfiguration(configuration, options...)
}

func (configuration QuantifierConfiguration) HasDirectory() bool {
	return len(configuration.directory) > 0
}

func (configuration QuantifierConfiguration) HasMain() bool {
	return len(configuration.main) > 0
}

func (configuration QuantifierConfiguration) HasBinary() bool {
	return len(configuration.binary) > 0
}

func (configuration QuantifierConfiguration) HasDump() bool {
	return configuration.dump != nil
}

func (configuration QuantifierConfiguration) HasTargets() bool {
	return len(configuration.targets) > 0
}

func (configuration QuantifierConfiguration) HasLandfill() bool {
	return len(configuration.landfill) > 0
}

func (configuration QuantifierConfiguration) HasTimeout() bool {
	return configuration.timeout > 0
}

func (configuration QuantifierConfiguration) Targets() []TargetsOption {
	return configuration.targets
}

func (configuration QuantifierConfiguration) Dump() *obj.Dump {
	return configuration.dump
}

func (runner *Runner[In, Out]) Execute(
	context context.Context, directory string, binary string, plan fi.AttackPlan,
) (Out, error) {
	attack, err := runner.Configure(context, directory, plan)
	if err != nil {
		var zero Out
		return zero, err
	}

	output, err := runner.QEMU(context, binary, attack)

	if rmErr := os.Remove(attack); rmErr != nil {
		return output, errors.Join(rmErr, err)
	}

	return output, err
}

func (runner *Runner[In, Out]) Prepare(
	context context.Context, input In, configuration *QuantifierConfiguration,
) error {
	if !configuration.HasMain() {
		var err error
		if configuration.main, err = runner.Generate(context, configuration.directory, input); err != nil {
			return err
		}
	}

	if !configuration.HasBinary() {
		var err error
		if configuration.binary, err = runner.Build(context, configuration.directory, configuration.main); err != nil {
			return err
		}

	}

	if !configuration.HasLandfill() {
		var err error
		if configuration.landfill, err = runner.Dump(context, configuration.directory, configuration.binary); err != nil {
			return err
		}
	}

	if !configuration.HasDump() {
		dump, err := obj.ParseFile(configuration.landfill)
		if err != nil {
			return err
		}
		configuration.dump = &dump
	}

	return nil
}

func (runner *Runner[In, Out]) Forall(
	ctx context.Context,
	configuration QuantifierConfiguration,
	inputs iter.Seq2[int, In],
	predicate func(input In, output Out, plan fi.AttackPlan) (bool, error),
) (bool, error) {
	planner := fi.NewAttackPlanner()
	for _, input := range inputs {
		runner.Prepare(ctx, input, &configuration)
		targets := make([]fi.Target, 0)
		for _, option := range configuration.Targets() {
			targets = append(targets, option(configuration.Dump())...)
		}

		for _, plan := range planner.Plan(targets...) {
			execCTX, cancel := context.WithTimeout(ctx, configuration.timeout)
			output, err := runner.Execute(
				execCTX, configuration.directory, configuration.binary, plan,
			)
			cancel()

			if err != nil {
				return true, err
			}

			if ok, err := predicate(input, output, plan); !ok {
				return false, err
			}
		}
	}

	return true, nil
}

type ParallelQuantifierOption func(configuration *ParallelQuantifierConfiguration)

func WithPool(pool int) ParallelQuantifierOption {
	return func(configuration *ParallelQuantifierConfiguration) {
		configuration.pool = pool
	}
}

func WithBatch(batch int32) ParallelQuantifierOption {
	return func(configuration *ParallelQuantifierConfiguration) {
		configuration.batch = batch
	}
}

type ParallelQuantifierConfiguration struct {
	QuantifierConfiguration
	pool int
	batch int32
}

func NewParallelQuantifierConfiguration(base QuantifierConfiguration, options ...ParallelQuantifierOption) ParallelQuantifierConfiguration {
	var configuration ParallelQuantifierConfiguration
	configuration.QuantifierConfiguration = base
	for idx := range options {
		options[idx](&configuration)
	}
	return configuration
}

func (runner *Runner[In, Out]) ForallParallel(
	ctx context.Context,
	configuration ParallelQuantifierConfiguration,
	inputs iter.Seq2[int, In],
	predicate func(input In, output Out, plan fi.AttackPlan) (bool, error),
) (bool, error) {
	pool := pond.NewResultPool[bool](configuration.pool, pond.WithContext(ctx))
	defer pool.StopAndWait()

	var counter atomic.Int32
	group := pool.NewGroup()

	planner := fi.NewAttackPlanner()
	for _, input := range inputs {
		runner.Prepare(ctx, input, &configuration.QuantifierConfiguration)
		targets := make([]fi.Target, 0)
		for _, option := range configuration.Targets() {
			targets = append(targets, option(configuration.Dump())...)
		}

		for _, plan := range planner.Plan(targets...) {
			counter.Add(1)
			group.Submit(func() bool {
				defer counter.Add(-1)

				execCTX, cancel := context.WithTimeout(ctx, configuration.timeout)
				output, err := runner.Execute(
					execCTX, configuration.directory, configuration.binary, plan,
				)
				cancel()

				if err != nil {
					return true
				}

				if ok, _ := predicate(input, output, plan); !ok {
					return false
				}

				if err := recover(); err != nil {
					return false
				}

				return true
			})

			if counter.Load() >= configuration.batch {
				results, err := group.Wait()
				for _, result := range results {
					if !result {
						return false, err
					}
				}
			}
		}
	}

	results, err := group.Wait()
	for _, result := range results {
		if !result {
			return false, err
		}
	}

	return true, nil
}
