package objects

import (
	"fmt"

	"github.com/GoHSM/context"
)


func ListObjectsMenu(p *context.AppContext) (error) {
	
	selection, err := selectObjectType()
	if err != nil {
		return err
	}

	objList, err := ListObjects(p, selection)
	if err != nil {
		return err
	}

	err = listAttributes(p, objList)
	if err != nil {
		return err
	}

	selection, err = selectAction()
	if err != nil {
		return err
	}

	switch selection {
	case "Exit":
		return nil
	case "Encrypt":
		fmt.Println("Encrypt")
		obj, err := SelectObject(p, objList)
		if err != nil {
			return err
		}

		fmt.Println("Object selected: ", obj)

		// TODO: this will need to be changed
		p.SymKey = obj
	case "Decrypt":
		fmt.Println("Decrypt")
	case "Wrap":
		fmt.Println("Wrap")
	case "Unwrap":
		fmt.Println("Unwrap")
	case "Sign":
		fmt.Println("Sign")
	case "Verify":
		fmt.Println("Verify")
	}

	return nil
}
