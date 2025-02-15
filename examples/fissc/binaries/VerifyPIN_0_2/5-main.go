package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hyperproperties/gorrupt/examples/fissc/VerifyPIN_0/pkg"
)

func main() {
	var input pkg.VerifyPINInput
	if err := json.Unmarshal([]byte{0x7b, 0x22, 0x55, 0x73, 0x65, 0x72, 0x50, 0x49, 0x4e, 0x22, 0x3a, 0x5b, 0x32, 0x31, 0x36, 0x2c, 0x31, 0x34, 0x39, 0x2c, 0x32, 0x35, 0x2c, 0x34, 0x32, 0x5d, 0x7d}, &input); err != nil {
		panic(err)
	}
	output := input.Call()
	bytes, err := json.Marshal(output)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(bytes))
}
