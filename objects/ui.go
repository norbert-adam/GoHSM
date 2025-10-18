package objects

import (
	"fmt"
	"errors"
)


func selectObjectType() (string, error) {

	options := map[int]string{
		1: "All",
		2: "Keys",
		3: "Certs",
	}

	fmt.Printf("Select the type of option you want to list:\n")
	fmt.Printf("\t1. All Objects\n")
	fmt.Printf("\t2. Keys\n")
	fmt.Printf("\t3. Certificates\n")

	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Incorrect input: %v", err)
		return "", errors.New(newErr)
	}
	if selection < 1 || selection > len(options) {
		newErr := fmt.Sprintf("incorrect input - selected option must be between 1 and %d", len(options))
		return "", errors.New(newErr)
	}

	return options[selection], nil
}


func selectAction() (string, error) {
	options := map[int]string{
		1: "Delete",
		2: "Encrypt",
		3: "Decrypt",
		4: "Wrap",
		5: "Unwrap",
		6: "Sign",
		7: "Verify",
		8: "Exit",
	}

	fmt.Println("")
	fmt.Println(" ----------------------------")
	fmt.Printf("| SELECT WHAT YOU WANT TO DO |\n")
	fmt.Println(" ----------------------------")
	fmt.Printf("\t1. Delete\n")
	fmt.Printf("\t2. Encrypt\n")
	fmt.Printf("\t3. Decrypt\n")
	fmt.Printf("\t4. Wrap\n")
	fmt.Printf("\t5. Unwrap\n")
	fmt.Printf("\t6. Sign\n")
	fmt.Printf("\t7. Verify\n")
	fmt.Printf("\t8. Exit\n")

	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Incorrect input: %v", err)
		return "", errors.New(newErr)
	}
	if selection < 1 || selection > len(options) {
		newErr := fmt.Sprintf("Incorrect input - selected option must be between 1 and %d", len(options))
		return "", errors.New(newErr)
	}

	return options[selection], nil
}
