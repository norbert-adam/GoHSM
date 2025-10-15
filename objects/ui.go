package objects

import (
	"fmt"
	"errors"

	"github.com/GoHSM/context"

	"github.com/miekg/pkcs11"
)


func selectOption() (string, error) {

	options := map[int]string{
		1: "All",
		2: "Keys",
		3: "Certs",
	}

	fmt.Printf("Select the type of option you want to list:\n")
	fmt.Printf("\t1. All Objects\n")
	fmt.Printf("\t2. Keys\n")
	fmt.Printf("\t3. Certificates\n")

	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Incorrect input: %v", err)
		return "", errors.New(newErr)
	}
	if selection < 1 || selection > len(options) {
		newErr := fmt.Sprintf("incorrect input - selected option must be between 1 and %d", len(options))
		return "", errors.New(newErr)
	}

	return options[selection], nil
}


func selectAction() (string, error) {
	options := map[int]string{
		1: "Delete",
		2: "Encrypt",
		3: "Decrypt",
		4: "Wrap",
		5: "Unwrap",
		6: "Sign",
		7: "Verify",
		8: "Exit",
	}

	fmt.Printf("Select the type of option you want to list:\n")
	fmt.Printf("\t1. Delete\n")
	fmt.Printf("\t2. Encrypt\n")
	fmt.Printf("\t3. Decrypt\n")
	fmt.Printf("\t4. Wrap\n")
	fmt.Printf("\t5. Unwrap\n")
	fmt.Printf("\t6. Sign\n")
	fmt.Printf("\t7. Verify\n")
	fmt.Printf("\t8. Exit\n")

	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Incorrect input: %v", err)
		return "", errors.New(newErr)
	}
	if selection < 1 || selection > len(options) {
		// TODO: replace hard-coded number with the last key of the map
		return "", errors.New("incorrect input - selected option must be between 1 and 8")
	}

	return options[selection], nil
}


func SelectObject(p *context.AppContext, objectList []pkcs11.ObjectHandle) (pkcs11.ObjectHandle, error) {
	
	var selection int
	fmt.Println("Select the object: ")
	for i, obj := range objectList {
		objType, err := getObjectType(p, obj)
		if err != nil {
			return 0, err
		}
		attrTemplate := getAttributeTemplate("short", objType)

		attrs, err := p.P11.GetAttributeValue(p.Session, obj, attrTemplate)
		if err != nil {
			newErr := fmt.Sprint("Error getting attributes: ", err)
			return 0, errors.New(newErr)
		}
		fmt.Printf("%d. Object: %v (object handle: %d / label %s)\n", i, AttrToString(attrs[0]), obj, attrs[1].Value)
	}

	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Incorrect input: %v", err)
		return 0, errors.New(newErr)
	}
	if selection < 0 || selection > len(objectList) {
		newErr := fmt.Sprintf("incorrect input - selected option must be between 0 and %d", len(objectList)-1)
		return 0, errors.New(newErr)
	}

	return objectList[selection], nil
}
