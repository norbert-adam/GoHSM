package main

// TODO: Read config file to get the library paths
// 


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
}
