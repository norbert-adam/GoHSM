package generate

import (
	"fmt"

	"github.com/GoHSM/objects"
	"github.com/GoHSM/userif"
	"github.com/GoHSM/context"
	
	"github.com/miekg/pkcs11"
)


func GenDelWorkflow(p *context.AppContext, task string) (pkcs11.ObjectHandle, error) {

	switch task {
	case "Delete":
		_, err := DeleteWorkflow(p)
		if err != nil {
			return 0, err
		}
	case "Generate":
		_, err := GenerateWorkflow()
		if err != nil {
			return 0, err
		}
	}
	return 0, nil
}


func DeleteWorkflow(p *context.AppContext) (pkcs11.ObjectHandle, error) {
	userif.ClearTerminal()
	objs, err := objects.ListObjects(p, "All")
	if err != nil {
		return 0, err
	}
	obj, err := objects.SelectObject(p, objs)
	if err != nil {
		return 0, err
	}
	err = DeleteObject(p, obj)
	if err != nil {
		return 0, err
	}
	
	fmt.Printf("Object %d successfully deleted!\n", obj)
	return 0, nil
}


func GenerateWorkflow() (pkcs11.ObjectHandle, error) {
	userif.ClearTerminal()
	action, err := GenDetails()
	if err != nil {
		return 0, err
	}

	switch action {
	case "AES":
		fmt.Println("AES")
	case "RSA":
		fmt.Println("RSA")
	case "ECC":
		fmt.Println("ECC")
	case "EDD":
		fmt.Println("EDD")
	}

	fmt.Printf("%s key successfully generated - key handle: %d\n", action, 0)

	return 0, nil
}


func GenDetails() (string, error) {
	options := map[int]string {
		1: "AES",
		2: "RSA",
		3: "ECC",
		4: "EDD",
	}

	var selection int
	fmt.Println("Select the type of key you want to generate:")
	fmt.Println("\t1. AES")
	fmt.Println("\t2. RSA")
	fmt.Println("\t3. ECC")
	fmt.Println("\t4. EDD")

	_, err := fmt.Scan(&selection)
	if err != nil {
		return "", err
	}
	return options[selection], nil
}
