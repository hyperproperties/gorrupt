# gorrupt
```
go build -o arithmetic.main ./examples/arithmetic/main.go
go tool objdump ./arithmetic.main > arithmetic.disassembly
```

```
go run ./cmd/main.go --elf="./arithmetic.main" --objdump="./arithmetic.disassembly"
```