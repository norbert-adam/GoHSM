package main

// TODO: Read config file to get the library paths
// TODO: Print error messages to stderr
// TODO: Create a map of the slot indexes, slot IDs, and maybe slot labels
// TODO: Check for invalid slots - e.g., in SoftHSM, there is always 1 slot that is not initialized/has no label
// TODO: Implement logging

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"

	"github.com/GoHSM/utils"
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

	// Select from options:
		// list all objects,
		// key generation/deletion,
		// encryption/decryption,
		// wrapping/unwrapping,
		// sing/verify.

	err = p.FindObjectsInit(session, []*pkcs11.Attribute{})
	if err != nil {
		fmt.Println("Error initializing FindObjects: ", err)
		return
	}
	defer p.FindObjectsFinal(session)

	for {
		objs, _, err := p.FindObjects(session, 1)
		if err != nil {
			fmt.Println("Error finding objects.")
			return
		}

		if len(objs) == 0 {
			break
		}

		for _, obj := range objs {
			attrs, err := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
				// pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
				// pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
			})
			if err != nil {
				fmt.Printf("Error reading object %v: %v\n", obj, err)
				return
			}

			fmt.Printf("Object handle %v:\n", obj)
			for _, a := range attrs {
				fmt.Printf("\t%v\n", utils.AttrToString(a))
			}
		}
	}
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

func processSlots (p *pkcs11.Ctx) ([]uint, error) {

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

	if selection > len(slots) - 1 || selection < 0 { 
		return 0, errors.New("Invalid input for slot selection")
	}

	slot := slots[selection]

	return slot, nil
}
