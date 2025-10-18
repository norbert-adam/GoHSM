package userif

import (
	"fmt"
	"os"
	"os/exec"
)

func ClearTerminal() {
	fmt.Println("Hello world.")
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}
