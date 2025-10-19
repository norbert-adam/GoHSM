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
		err := DeleteWorkflow(p)
		if err != nil {
			return 0, err
		}
	case "Generate":
		err := GenerateWorkflow(p)
		if err != nil {
			return 0, err
		}
	}
	return 0, nil
}


func DeleteWorkflow(p *context.AppContext) (error) {
	userif.ClearTerminal()
	objs, err := objects.ListObjects(p, "All")
	if err != nil {
		return err
	}
	obj, err := objects.SelectObject(p, objs)
	if err != nil {
		return err
	}
	err = DeleteObject(p, obj)
	if err != nil {
		return err
	}
	
	fmt.Printf("Object %d successfully deleted!\n", obj)
	return nil
}

func GenerateWorkflow(p *context.AppContext) (error) {
	userif.ClearTerminal()
	action, err := GenDetails()
	if err != nil {
		return err
	}

	userif.ClearTerminal()
	switch action {
	case "AES":
		aesKey, err := GenerateAES(p)
		if err != nil {
			return err
		}	
		p.SymKey = aesKey
		return nil
	case "RSA":
		rsaPub, rsaPriv, err := GenerateRSA(p)
		if err != nil {
			return err
		}
		p.AsKeyPub = rsaPub
		p.AsKeyPriv = rsaPriv
		return nil
	case "ECC":
		eccPub, eccPriv, err := GenerateECC(p)
		if err != nil {
			return err
		}
		p.AsKeyPub = eccPub
		p.AsKeyPriv = eccPriv
		return nil
	case "EDD":
		fmt.Println("EDD")
	}

	return nil
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
