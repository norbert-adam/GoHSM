package userif

import (
	"fmt"
	"os"
	"os/exec"
	"errors"
)

func ClearTerminal() {
	fmt.Println("Hello world.")
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}


func OptionSelectGenerate() (string, error) {
	
	var selection int
	fmt.Println("Use key from HSM or generate new key?")
	fmt.Printf("\t1. Select key from HSM\n")
	fmt.Printf("\t2. Generate new key\n")

	_, err := fmt.Scan(&selection)
	
	if err != nil {
		newErr := fmt.Sprint("Error reading input: ", err)
		return "", errors.New(newErr)
	}

	switch selection {
	case 1:
		return "Select", nil
	case 2:
		return "Generate", nil
	default:
		return "", errors.New("Invalid selection - input must be 1 or 2.")
	}
}
