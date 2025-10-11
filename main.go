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

	// "github.com/GoHSM/utils"
	// "github.com/GoHSM/objects"
	// "github.com/GoHSM/generate"
	"github.com/GoHSM/aes"

	"github.com/miekg/pkcs11"
)

func main() {

	// Initialize PKCS11 module/library
	p := pkcs11.New("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
	err := p.Initialize()
	if err != nil {
		fmt.Println("Error loading pkcs11 module: ", err)
		return
	}
	defer p.Destroy()
	defer p.Finalize()

	fmt.Println("PKCS11 Module successfully initialized!")

	slots, err := processSlots(p)
	if err != nil {
		fmt.Println(err)
		return
	}
	slot, err := selectSlot(slots)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Slot selected: %d\n", slot)

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		fmt.Printf("Error opening session to slot %d: %s\n", slot, err)
		return
	}
	defer p.CloseSession(session)
	fmt.Printf("Session successfully opened (session %d)\n", session)

	password, err := getPassword()
	if err != nil {
		fmt.Println(err)
		return
	}

	err = p.Login(session, pkcs11.CKU_USER, password)
	if err != nil {
		fmt.Printf("Error during login: %s\n", err)
		return
	}
	defer p.Logout(session)
	fmt.Println("Successful login!")



	aesKey, err := aes.GenerateAES(p, session)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	aes.WrapAES(p, session, aesKey)







	// rsaPub, rsaPriv, err := generate.GenerateRSA(p, session)
	// if err != nil {
	// 	fmt.Println("Error: ", err)
	// 	return
	// }

	// fmt.Println("AES Key: ", aesKey)
	// fmt.Println("RSA Pub: ", rsaPub)
	// fmt.Println("RSA Priv: ", rsaPriv)
	// generate.GenerateECC(p, session)
	
	// selection, err := printMenu(session, slot)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// switch selection {
	// case "listObjs", "listKeys",  "listCerts":
	// 	objects.ListObjects(p, session, selection)
	// case "genDel":
	// 	fmt.Println("Generate/Delete selected.")
	// 	selection, err := genQuery()
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	// 	if selection == 1 {
	// 		selection, err := generate.GenDetails()
	// 		if err != nil {
	// 			fmt.Sprint("Error reading input: ", err)
	// 			return
	// 		}
	// 		switch selection {
	// 		case 1:
	// 			aesKey, err := generate.GenerateAES(p, session)
	// 			if err != nil {
	// 				fmt.Println("Error during key generation: ", err)
	// 				return
	// 			}
	// 			fmt.Println("AES key generated - object handle: ", aesKey)
	// 		case 2:
	// 			generate.GenerateRSA(p)
	// 		}
	// 	}
	// 	if selection == 2 {
	// 		fmt.Println("Delete key was selected.")
	// 	}

	// case "encDec":
	// 	fmt.Println("Encryption/Decryption selected.")
	// case "wrapUnwr":
	// 	fmt.Println("Wrap/Unwrap selected.")
	// case "signVer":
	// 	fmt.Println("Sign/Verify selected.")
	// }
}



func genQuery() (int, error) {
	var selection int
	fmt.Println("Select what you want to do:")
	fmt.Println("\t1. Generate Key")
	fmt.Println("\t2. Delete Key")
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprint("Error reading input: ", err)
		return 0, errors.New(newErr)
	}
	
	return selection, nil
}


func printMenu(session pkcs11.SessionHandle, slot uint) (string, error) {
	options := map[int]string{
		1: "listObjs",
		2: "listKeys",
		3: "listCerts",
		4: "genDel",
		5: "encDec",
		6: "wrapUnwr",
		7: "signVer",
	}

	fmt.Printf("LOGGED IN TO SLOT %d (SESSION NO. %d)\n", slot, session)
	fmt.Printf("Available actions: \n")
	fmt.Printf("\t1. List All Objects\n")
	fmt.Printf("\t2. List Keys\n")
	fmt.Printf("\t3. List Certificates\n")
	fmt.Printf("\t4. Generate/Delete Object\n")
	fmt.Printf("\t5. Encrypt/decrypt\n")
	fmt.Printf("\t6. Wrap/Unwrap\n")
	fmt.Printf("\t7. Sign/verify\n")

	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Incorrect input: %v", err)
		return "", errors.New(newErr)
	}
	if selection < 1 || selection > 5 {
		return "", errors.New("incorrect input - selected option must be between 1 and 5")
	}

	return options[selection], nil
}

func getPassword() (string, error) {
	fmt.Printf("Being login process - please provide password: ")
	var pwd string
	_, err := fmt.Scan(&pwd)
	if err != nil {
		newErr := fmt.Sprintf("Invalid password provided: %s\n", err)
		return "", errors.New(newErr)
	}

	return pwd, nil
}

func processSlots(p *pkcs11.Ctx) ([]uint, error) {

	slots, err := p.GetSlotList(true)
	if err != nil {
		newErr := fmt.Sprintf("Error listing slots: %s\n", err)
		return nil, errors.New(newErr)
	}

	fmt.Println("Available slots:")
	for i, slot := range slots {
		tInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			newErr := fmt.Sprintf("Error loading token info: %s\n", err)
			return nil, errors.New(newErr)
		}
		var label string
		if tInfo.Label == "" {
			label = "N/A"
		} else {
			label = tInfo.Label
		}
		fmt.Printf("\t%d. Slot: %s (%d)\n", i, label, slot)
	}
	return slots, nil
}

func selectSlot(slots []uint) (uint, error) {

	fmt.Printf("Select slot: ")
	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Invalid input for slot selection: %s\n", err)
		return 0, errors.New(newErr)
	}

	if selection > len(slots)-1 || selection < 0 {
		return 0, errors.New("Invalid input for slot selection")
	}

	slot := slots[selection]

	return slot, nil
}
