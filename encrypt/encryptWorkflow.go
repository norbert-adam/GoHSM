package encrypt

import (
	"fmt"
	
	"github.com/GoHSM/context"
	"github.com/GoHSM/userif"
	"github.com/GoHSM/objects"
	"github.com/GoHSM/generate"

	"github.com/miekg/pkcs11"
)

func EncWorkflow(p *context.AppContext) error {
	// Select/generate key for encryption
		// Get object handle
		// Get key type
		// List available methods based on key type
		// Select encryption method
	// Select method for encryption
	// Select input for encryption
	// Select output for encryption

	nextAction, err := userif.OptionSelectGenerate()
	if err != nil {
		return err
	}

	var key pkcs11.ObjectHandle

	switch nextAction {
	case "Select":
		objs, err := objects.ListObjects(p, "Keys")
		if err != nil {
			return err
		}
		fmt.Println("Got this far.")
		key, err = objects.SelectObject(p, objs)
		if err != nil {
			fmt.Println(err)
			return err
		}
	case "Generate":
		fmt.Println("Encrypt --> Generate.")
		key, err = generate.GenDelWorkflow(p, nextAction)
		if err != nil {
			return err
		}
		fmt.Println(key)
	}

	keyType, err := objects.GetKeyType(p, key)
	if err != nil {
		return err
	}

	switch keyType {
	case pkcs11.CKK_AES:
		fmt.Println("AES KEY!")
	case pkcs11.CKK_RSA:
		fmt.Println("RSA KEY!")
	}

	return nil
}
