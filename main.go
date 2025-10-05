package main

// TODO: Read config file to get the library paths
// TODO: Print error messages to stderr


import (
	"fmt"
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
	
	slots, err := p.GetSlotList(true)
	if err != nil {
		fmt.Println("Error listing slots: ", err)
		return
	}

	fmt.Println("Available slots:")
	for i, slot := range slots {
		tInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			fmt.Println("Error loading token info: ", err)
		}
		var label string
		if tInfo.Label == "" {
			label = "N/A"
		} else {
			label = tInfo.Label
		}
		fmt.Printf("\t%d. Slot: %s (%d)\n", i, label, slot)
	}
}
