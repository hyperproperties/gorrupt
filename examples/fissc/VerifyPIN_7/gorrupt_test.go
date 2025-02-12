package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
	
	"github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_7/pkg"
	"github.com/hyperproperties/gorrupt/pkg/fi"
	"github.com/hyperproperties/gorrupt/pkg/fi/tester"
	"github.com/stretchr/testify/assert"
)

func Test(t *testing.T) {
	context, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	os.Mkdir("./tmp", os.ModePerm)
	defer os.RemoveAll("./tmp")

	runner := tester.NewRunner[pkg.VerifyPINInput, pkg.VerifyPINOutput](
		"/home/andreas/git/qemu-fi/build-arm/qemu-arm",
		"github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_7/pkg",
		"pkg", "VerifyPIN",
		"GOARCH=arm", "GOOS=linux",
	)

	tester.CheckParallel(context, runner,
		func(e0, e1 pkg.VerifyPINOutput, attack fi.Attack) {
			var buffer bytes.Buffer
			attack.WriteAttack(&buffer)
			attackIdentifier := "attack: [" + strings.TrimSpace(buffer.String()) + "]"
			assert.Equal(t, e0.Ret0, e1.Ret0, attackIdentifier)
		},
	)
}
