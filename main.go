package main

// TODO: Read config file to get the library paths
// TODO: Print error messages to stderr
// TODO: Create a map of the slot indexes, slot IDs, and maybe slot labels
// TODO: Check for invalid slots - e.g., in SoftHSM, there is always 1 slot that is not initialized/has no label


import (
	"fmt"
	"github.com/miekg/pkcs11"
	"errors"
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
	num, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Invalid input for slot selection: %s\n", err)
		return 0, errors.New(newErr)
	}
	fmt.Println("Num read: ", num)

	if selection > len(slots) - 1 || selection < 0 { 
		return 0, errors.New("Invalid input for slot selection")
	}

	slot := slots[selection]

	return slot, nil
}
