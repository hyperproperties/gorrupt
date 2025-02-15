package execx

import (
	"context"
	"errors"
	"log"
	"os/exec"
	"syscall"
	"time"
)

/*
log.Println("starting")
shArgs := []string{"-c", "sleep 10"}
cmd := exec.Command("sh", shArgs...)
cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

type cmdResult struct {
    outb []byte
    err  error
}
cmdDone := make(chan cmdResult, 1)
go func() {
    outb, err := cmd.CombinedOutput()
    cmdDone <- cmdResult{outb, err}
}()

select {
case <-time.After(2 * time.Second):
    syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
    log.Fatal("signal: killed")
case <-cmdDone:
    log.Println("finished")
}
*/

func Example() {
    context, cancel := context.WithTimeout(context.Background(), time.Minute)
    defer cancel()

    var output []byte
    RunCommandContext(context, func(command *exec.Cmd) (err error) {
        output, err = command.CombinedOutput()
        return err
    }, "go", "build")

    log.Println(string(output))
}

func RunCommandContext(ctx context.Context, run func(command *exec.Cmd) error, name string, arg ...string) error {
    command := exec.CommandContext(ctx, name, arg...)
    command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pdeathsig: syscall.SIGKILL,
	}

    done := make(chan error, 1)
    go func()  {
        done <- run(command)
    }()

    select {
    case err := <-done:
        return err
    case <-ctx.Done():
        if command.Process != nil {
            return errors.Join(ctx.Err(), syscall.Kill(-command.Process.Pid, syscall.SIGKILL))
        }
        return ctx.Err()
    }
}