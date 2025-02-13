package main

import (
	"context"
	"testing"
	"time"
	
	"github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_0/pkg"
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/fi/tester"
)

func Test(t *testing.T) {
	context, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	runner := tester.NewRunner[pkg.VerifyPINInput, pkg.VerifyPINOutput](
		"/home/andreas/git/qemu-fi/build-arm/qemu-arm",
		"github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_0/pkg",
		"pkg", "VerifyPIN",
		"GOARCH=arm", "GOOS=linux",
	)

	pack := "github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_0/pkg"
	verifyPIN := tester.FunctionInPackage(pack, "VerifyPIN")
	pinCompare := tester.FunctionInPackage(pack, "PINCompare")

	err := tester.CheckParallel(context, runner,
		func(e0, e1 pkg.VerifyPINOutput, attack fi.Attack) {
			if !e1.Countermeasure {
				t.Error("Undetected: " + attack.String())
			}
			if e0.Ret0 != e1.Ret0 {
				t.Error("OD Violation: " + attack.String())
			}
			if !(e1.Countermeasure && !e1.Ret0) {
				t.Error("Undetected access: " + attack.String())
			}
		},
		tester.BFRLinearTargets(verifyPIN, pinCompare),
	)

	if err != nil {
		t.Error(err)
	}
}
