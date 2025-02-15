package main

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	"github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_5/pkg"
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/fi/arm"
	"github.com/hyperproperties/gorrupt/pkg/fi/tester"
	"github.com/hyperproperties/gorrupt/pkg/iterx"
	"github.com/hyperproperties/gorrupt/pkg/quick"
)

func Test(t *testing.T) {
	context, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	runner := tester.NewRunner[pkg.VerifyPINInput, pkg.VerifyPINOutput](
		"/home/andreas/git/qemu-fi/build-arm/qemu-arm",
		"github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_5/pkg",
		"pkg", "VerifyPIN",
		"GOARCH=arm", "GOOS=linux",
	)

	pack := "github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_5/pkg"
	verifyPIN := tester.FunctionInPackage(pack, "VerifyPIN")
	pinCompare := tester.FunctionInPackage(pack, "PINCompare")

	e0Dir := path.Join(".", quick.String(32, quick.USAlphabet...))
	os.MkdirAll(e0Dir, os.ModePerm)
	defer os.RemoveAll(e0Dir + "/")

	e1Dir := path.Join(".", quick.String(32, quick.USAlphabet...))
	os.MkdirAll(e1Dir, os.ModePerm)
	defer os.RemoveAll(e1Dir + "/")

	// forall e0.
	ok, err := runner.Forall(
		context, tester.NewQuantifierConfiguration(
			tester.WithDirectory(e0Dir),
			tester.WithTimeout(time.Minute),
		),
		iterx.Once2(quick.New[pkg.VerifyPINInput]()),
		func(
			e0Input pkg.VerifyPINInput, e0Output pkg.VerifyPINOutput, plan fi.AttackPlan,
		) (bool, error) {
			
			// forall e1 under BFR.
			return runner.ForallParallel(
				context, tester.NewQuantifierConfiguration(
					tester.WithTargetOptions(
						tester.LinearSearchTargets(
							arm.NewBFRLinearSearch(),
							verifyPIN, pinCompare,
						),
						tester.LinearSearchTargets(
							arm.NewICLinearSearch(),
							verifyPIN, pinCompare,
						),
						tester.LinearSearchTargets(
							arm.NewISLinearSearch(),
							verifyPIN, pinCompare,
						),
					),
					tester.WithDirectory(e1Dir),
					tester.WithTimeout(time.Minute),
				).Parallel(
					tester.WithPool(512),
					tester.WithBatch(4096),
				),
				iterx.Once2(e0Input),
				func(
					e1Input pkg.VerifyPINInput, e1Output pkg.VerifyPINOutput, plan fi.AttackPlan,
				) (bool, error) {
					if !e1Output.Countermeasure {
						t.Error("Undetected: " + plan.String())
					}
					if e0Output.Ret0 != e1Output.Ret0 {
						t.Error("OD Violation: " + plan.String())
					}
					if !e1Output.Countermeasure && e1Output.Ret0 == pkg.TrueHB {
						t.Error("Undetected access: " + plan.String())
					}
					return true, nil
				},
			)
		},
	)

	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.Error()
	}
}
