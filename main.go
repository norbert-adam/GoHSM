package main

// TODO: Read config file to get the library paths
// TODO: Print error messages to stderr
// TODO: Create a map of the slot indexes, slot IDs, and maybe slot labels
// TODO: Check for invalid slots - e.g., in SoftHSM, there is always 1 slot that is not initialized/has no label
// TODO: Implement logging
// Select from options:
// list all objects,
// key generation/deletion,
// encryption/decryption,
// wrapping/unwrapping,
// sing/verify.
// TODO: rewrite generating functions to check for whether key size is provided or not, if not, query for value

import (
	"errors"
	"fmt"

	"github.com/GoHSM/context"
	"github.com/GoHSM/encrypt"
	"github.com/GoHSM/generate"
	"github.com/GoHSM/objects"
	"github.com/GoHSM/userif"
	"github.com/miekg/pkcs11"
)


func main() {

	userif.ClearTerminal()
	printLogo()
	p, err := context.InitializeContext()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer p.P11.Destroy()
	defer p.P11.Finalize()
	defer p.P11.Logout(p.Session)
	
	userif.ClearTerminal()		
	selection, err := printMenu(p)
	if err != nil {
		fmt.Println(err)
		return
	}

	switch selection {
	case "List":
		userif.ClearTerminal()
		err = objects.ListObjectsMenu(p)
		if err != nil {
			fmt.Println(err)
			return
		}
	case "Generate", "Delete":
		_, err := generate.GenDelWorkflow(p, selection)
		if err != nil {
			fmt.Println(err)
			return
		}
	case "Encrypt":
		p.Action = selection
		nextAction, err := userif.OptionSelectGenerate()
		if err != nil {
			fmt.Println(err)
			return
		}

		switch nextAction {
		case "Select":
			objs, err := objects.ListObjects(p, "Keys")
			if err != nil {
				fmt.Println(err)
				return
			}
			selObj, err := objects.SelectObject(p, objs)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println("Selected object: ", selObj)
		case "Generate":
			fmt.Println("Encrypt --> Generate.")
		}
		err = encrypt.EncryptAes(p, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, nil)})
		if err != nil {
			fmt.Println(err)
			return
		}
		
		fmt.Println("Encrypt was selected.")
	case "Exit":
		fmt.Println("Exiting GoHSM... Goodbye!")
		return
	default:
		fmt.Println("Others were selected.")
	}
}


func printMenu(p *context.AppContext) (string, error) {
	options := map[int]string{
		1: "List",
		2: "Generate",
		3: "Delete",
		4: "Encrypt",
		5: "Decrypt",
		6: "Wrap",
		7: "Unwrap",
		8: "Sign",
		9: "Verify",
		10: "Exit",
	}

	fmt.Printf("LOGGED IN TO SLOT %d (SESSION NO. %d)\n", p.Slot, p.Session)
	fmt.Printf("Available actions: \n")
	fmt.Printf("\t1. List Objects\n")
	fmt.Printf("\t2. Generate Object\n")
	fmt.Printf("\t3. Delete Object\n")
	fmt.Printf("\t4. Encrypt\n")
	fmt.Printf("\t5. Decrypt\n")
	fmt.Printf("\t6. Wrap\n")
	fmt.Printf("\t7. Unwrap\n")
	fmt.Printf("\t8. Sign\n")
	fmt.Printf("\t9. Verify\n")
	fmt.Printf("\t10. Exit\n")

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

func printLogo() {
	logo := `░░      ░░░░      ░░░  ░░░░  ░░░      ░░░  ░░░░  ░░░░░░░
▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒   ▒▒   ▒▒▒▒▒▒▒
▓  ▓▓▓   ▓▓  ▓▓▓▓  ▓▓        ▓▓▓      ▓▓▓        ▓▓▓▓▓▓▓
█  ████  ██  ████  ██  ████  ████████  ██  █  █  ███████
██      ████      ███  ████  ███      ███  ████  ███████
                                                        `
	
	fmt.Println("")													
	fmt.Print(logo)
	fmt.Println("")

	fmt.Printf("\t-----------------\n")
	fmt.Printf("\tWELCOME TO GOHSM!\n")
	fmt.Printf("\t-----------------\n")
	fmt.Println("")
}
