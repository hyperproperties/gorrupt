package tester

import (
	"context"
	"errors"
	"os"
	"path"

	"github.com/alitto/pond/v2"
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/fi/arm"
	"github.com/hyperproperties/gorrupt/pkg/obj"
	"github.com/hyperproperties/gorrupt/pkg/quick"
)

// TODO: Figure out a better name.
func Setup[In, Out any](
	context context.Context, directory string, runner Runner[In, Out], input In,
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

func E0[In, Out any](context context.Context, runner Runner[In, Out], main string) (Out, error) {
	return runner.Go(context, main)
}

func E1[In, Out any](context context.Context, runner Runner[In, Out], directory string, binary string, plan fi.AttackPlan) (Out, error) {
	attack, err := runner.Configure(context, directory, plan)
	if err != nil {
		var zero Out
		return zero, err
	}
	defer os.Remove(attack)

	output, err := runner.QEMU(context, binary, attack)
	
	if rmErr := os.Remove(attack); rmErr != nil {
		return output, errors.Join(rmErr, err)
	}
	
	return output, err
}

func CheckParallel[In, Out any](context context.Context, runner Runner[In, Out], action func(e0, e1 Out, attack fi.Attack)) error {
	pool := pond.NewPool(512, pond.WithContext(context))
	input := quick.New[In]()

	directory := path.Join(".", "tmp", quick.String(32, quick.USAlphabet...))
	os.MkdirAll(directory, os.ModePerm)
	defer os.RemoveAll(directory + "/")

	main, binary, landfill, err := Setup(context, directory, runner, input)
	if err != nil {
		return err
	}


	// TODO: This should be a part of the strategy.
	dump, err := obj.ParseFile(landfill)
	if err != nil {
		return err
	}

	verifyPIN := dump.FirstFunctionInPackage(
		"github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_0/pkg", "VerifyPIN",
	)
	searcher := arm.NewBFRSearcher()
	targets := searcher.Instructions(verifyPIN.Instructions())

	e0, err := E0(context, runner, main)
	if err != nil {
		return err
	}

	// TODO: Make a strategy construction which returns an iterator of AttackPlan.
	for _, target := range targets {
		for _, attack := range target.Exhaustive(0) {
			pool.SubmitErr(func() error {
				e1, err := E1(context, runner, directory, binary, fi.AttackPlan{attack})
				if err != nil {
					return err
				}

				action(e0, e1, attack)

				return nil
			})
		}
	}

	return pool.Stop().Wait()
}