package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hyperproperties/gorrupt/pkg/fi/arm"
	"github.com/hyperproperties/gorrupt/pkg/obj"
)

func main() {
	flags := flag.NewFlagSet("flip", flag.ExitOnError)

	var objdumpPath string
	flags.StringVar(&objdumpPath, "objdump", "", "the path to the objdump for the elf file")

	flags.Parse(os.Args[1:])

	// Read go tool objdump output.
	objdumpReader, err := os.Open(objdumpPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer objdumpReader.Close()

	dump, err := obj.Parse(objdumpReader)
	if err != nil {
		log.Fatalln(err)
	}

	addition := dump.FunctionInPackageWithReceiver("main", "Calculator", "Addition")[0]

	targets := arm.NewBFRSearcher().Instructions(addition.Instructions())

	for _, target := range targets {
		fmt.Printf("	target: %v\n", target)
		for _, attack := range target.Exhaustive(0) {
			fmt.Printf("	attack: %v\n", attack)
		}
	}
}
