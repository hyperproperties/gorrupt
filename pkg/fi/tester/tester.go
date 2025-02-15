package tester

import (
	"context"
	"errors"
	"os"
	"path"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/fi/arm"
	"github.com/hyperproperties/gorrupt/pkg/obj"
	"github.com/hyperproperties/gorrupt/pkg/quick"
)

// TODO: Figure out a better name.
func Setup[In, Out any](
	context context.Context, directory string, runner *Runner[In, Out], input In,
) (main string, binary string, landfill string, err error) {
	// Generate entry-point.
	if main, err = runner.Generate(context, directory, input); err != nil {
		return
	}

	// Build the entry-point.
	if binary, err = runner.Build(context, directory, main); err != nil {
		return
	}

	// Generate objdump.
	if landfill, err = runner.Dump(context, directory, binary); err != nil {
		return
	}

	return
}

func E0[In, Out any](context context.Context, runner *Runner[In, Out], main string) (Out, error) {
	return runner.Go(context, main)
}

func E1[In, Out any](context context.Context, runner *Runner[In, Out], directory string, binary string, plan fi.AttackPlan) (Out, error) {
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

type InstructionsOption func(dump *obj.Dump) []obj.Instruction

func FunctionInPackage(pkg, function string) InstructionsOption {
	return func(dump *obj.Dump) []obj.Instruction {
		return dump.FirstFunctionInPackage(pkg, function).Instructions()
	}
}

type TargetsOption func(dump *obj.Dump) []fi.Target

func BFRLinearTargets(options ...InstructionsOption) TargetsOption {
	return func(dump *obj.Dump) []fi.Target {
		instructions := make([]obj.Instruction, 0)
		for _, option := range options {
			instructions = append(instructions, option(dump)...)
		}

		searcher := arm.NewBFRLinearSearch()
		bfrTargets := searcher.Instructions(instructions)
		
		targets := make([]fi.Target, len(bfrTargets))
		for i := range bfrTargets {
			targets[i] = bfrTargets[i]
		}

		return targets
	}
}

func LinearSearchTargets[T fi.Target](searcher fi.LinearSearcher[T], options ...InstructionsOption) TargetsOption {
	return func(dump *obj.Dump) []fi.Target {
		instructions := make([]obj.Instruction, 0)
		for _, option := range options {
			instructions = append(instructions, option(dump)...)
		}

		results := searcher.Instructions(instructions)
		targets := make([]fi.Target, len(results))
		for i := range results {
			targets[i] = results[i]
		}

		return targets
	}
}

func CheckParallel[In, Out any](
	ctx context.Context,
	runner *Runner[In, Out],
	action func(e0, e1 Out, plan fi.AttackPlan),
	options ...TargetsOption,
) error {
	pool := pond.NewPool(512, pond.WithContext(ctx))
	input := quick.New[In]()

	directory := path.Join(".", "tmp", quick.String(32, quick.USAlphabet...))
	os.MkdirAll(directory, os.ModePerm)
	defer os.RemoveAll("./tmp/")

	main, binary, landfill, err := Setup(ctx, directory, runner, input)
	if err != nil {
		return err
	}

	dump, err := obj.ParseFile(landfill)
	if err != nil {
		return err
	}

	targets := make([]fi.Target, 0)
	for _, option := range options {
		targets = append(targets, option(&dump)...)
	}

	e0, err := E0(ctx, runner, main)
	if err != nil {
		return err
	}

	var counter atomic.Int32
	planner := fi.NewAttackPlanner()
	for _, plan := range planner.Plan(targets...) {
		pool.SubmitErr(func() error {
			defer counter.Add(-1)
			
			executionCTX, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			e1, err := E1(executionCTX, runner, directory, binary, plan)
			if err != nil {
				return err
			}
	
			action(e0, e1, plan)
	
			return nil
		})

		counter.Add(1)

		// Ensure that only 2028 at most is active.
		for counter.Load() >= 2048 {}
	}
	

	pool.StopAndWait()

	return nil
}
