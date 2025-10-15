package objects

import (
	"fmt"

	"github.com/GoHSM/context"
)


func ListObjectsMenu(p *context.AppContext) (*context.AppContext, error) {
	
	selection, err := selectOption()
	if err != nil {
		return nil, err
	}

	objList, err := ListObjects(p, selection)
	if err != nil {
		return nil, err
	}
	fmt.Println("Returned object list: ", objList)

	err = listAttributes(p, objList)
	if err != nil {
		return nil, err
	}

	selection, err = selectAction()
	if err != nil {
		return nil, err
	}

	switch selection {
	case "Exit":
		return p, nil
	case "Encrypt":
		fmt.Println("Encrypt")
		obj, err := SelectObject(p, objList)
		if err != nil {
			return p, err
		}

		fmt.Println("Object selected: ", obj)
		p.Selected = obj
		p.Action = selection
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

	return p, nil
}
