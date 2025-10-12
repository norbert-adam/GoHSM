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
	// "encoding/binary"
	"errors"
	"fmt"

	// "github.com/GoHSM/objects"
	"github.com/GoHSM/context"
	"github.com/GoHSM/objects"
	// "github.com/GoHSM/generate"
	// "github.com/GoHSM/aes"
	// "github.com/GoHSM/utils"

	"github.com/miekg/pkcs11"
)


func main() {

	// Initialize PKCS11 module/library
	p, err := context.InitializeContext()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer p.P11.Destroy()
	defer p.P11.Finalize()
	defer p.P11.Logout(p.Session)
	
	p, err = objects.ListObjectsMenu(p)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Session: ", p.Session)
	fmt.Println("Selected: ", p.Selected)
	
	// selection, err := printMenu(session, slot)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// switch selection {
	// case "List":
	// 	err := objects.ListObjectsMenu(p, session)
	// 	if err != nil {
	// 		fmt.Println("Error: ", err)
	// 		return
	// 	}
	// case "Generate":
	// 	fmt.Println("Generate was selected.")
	// case "Delete":
	// 	fmt.Println("Generate was selected.")
	// case "Encrypt":
	// 	fmt.Println("Generate was selected.")
	// case "Decrypt":
	// 	fmt.Println("Generate was selected.")
	// case "Wrap":
	// 	fmt.Println("Generate was selected.")
	// case "Unwrap":
	// 	fmt.Println("Generate was selected.")
	// case "Sign":
	// 	fmt.Println("Generate was selected.")
	// case "Veriy":
	// 	fmt.Println("Generate was selected.")
	// }
}


func printMenu(session pkcs11.SessionHandle, slot uint) (string, error) {
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
	}

	fmt.Printf("LOGGED IN TO SLOT %d (SESSION NO. %d)\n", slot, session)
	fmt.Printf("Available actions: \n")
	fmt.Printf("\t1. List All Objects\n")
	fmt.Printf("\t2. Generate Object\n")
	fmt.Printf("\t3. Delete Object\n")
	fmt.Printf("\t4. Encrypt\n")
	fmt.Printf("\t5. Decrypt\n")
	fmt.Printf("\t6. Wrap\n")
	fmt.Printf("\t7. Unwrap\n")
	fmt.Printf("\t8. Sign\n")
	fmt.Printf("\t9. Verify\n")

	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Incorrect input: %v", err)
		return "", errors.New(newErr)
	}
	if selection < 1 || selection > 5 {
		return "", errors.New("incorrect input - selected option must be between 1 and 9")
	}

	return options[selection], nil
}

