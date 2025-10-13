package objects

import (
	"fmt"
	"errors"
	"encoding/binary"

	"github.com/GoHSM/utils"
	"github.com/GoHSM/context"

	"github.com/miekg/pkcs11"
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
	fmt.Println("Select the key that you want to use: ")
	for i, obj := range objectList {
		attrTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		}

		attrs, err := p.P11.GetAttributeValue(p.Session, obj, attrTemplate)
		if err != nil {
			newErr := fmt.Sprint("Error getting attributes: ", err)
			return 0, errors.New(newErr)
		}
		fmt.Printf("%d. Object: %v (object handle: %d / label %s)\n", i, utils.AttrToString(attrs[0]), obj, attrs[1].Value)
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


func ListObjects(p *context.AppContext, searchOption string) ([]pkcs11.ObjectHandle, error) {

	ctx := p.P11
	session := p.Session
	foundObjs := []pkcs11.ObjectHandle{}

	err := ctx.FindObjectsInit(session, []*pkcs11.Attribute{})
	if err != nil {
		newErr := fmt.Sprint("Error initializing FindObjects: ", err)
		return nil, errors.New(newErr)
	}
	defer ctx.FindObjectsFinal(session)

	for {
		objs, _, err := ctx.FindObjects(session, 1)
		if err != nil {
			newErr := fmt.Sprint("Error finding objects: ", err)
			return nil, errors.New(newErr)
		}

		if len(objs) == 0 {
			break
		}

		attr, err := ctx.GetAttributeValue(session, objs[0], []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			return nil, err
		}

		switch searchOption {
		case "All":
			foundObjs = append(foundObjs, objs[0])
		case "Keys":
			a := attr[0]
			aVal := binary.LittleEndian.Uint32(a.Value[:4])
			if aVal == pkcs11.CKO_SECRET_KEY || aVal == pkcs11.CKO_PUBLIC_KEY || aVal == pkcs11.CKO_PRIVATE_KEY {
				foundObjs = append(foundObjs, objs[0])
			}
		case "Certs":
			a := attr[0]
			aVal := binary.LittleEndian.Uint32(a.Value[:4])
			if aVal == pkcs11.CKO_CERTIFICATE {
				foundObjs = append(foundObjs, objs[0])
			}
		}	
	}
	
	return foundObjs, nil
}

func listAttributes(p *context.AppContext, objList []pkcs11.ObjectHandle) error {
	for _, obj := range objList {
		attr, err := p.P11.GetAttributeValue(p.Session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			return err
		}

		attrs, err := getObjectAttributes(p, obj, attr[0])
		if err != nil {
			newErr := fmt.Sprintf("Error reading object %v: %v\n", obj, err)
			return errors.New(newErr)
		}

		fmt.Printf("Object handle %v:\n", obj)
		for _, a := range attrs {
			fmt.Printf("\t%v\n", utils.AttrToString(a))
		}
	}
	
	return nil
}


func getObjectAttributes(p *context.AppContext, key pkcs11.ObjectHandle, keyType *pkcs11.Attribute) ([]*pkcs11.Attribute, error ){
	var attrList []*pkcs11.Attribute
	switch binary.LittleEndian.Uint32(keyType.Value[:4]) {
	case pkcs11.CKO_SECRET_KEY:
		attrList = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
		}
	case pkcs11.CKO_PUBLIC_KEY:
		attrList = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
		}
	case pkcs11.CKO_PRIVATE_KEY:
		attrList = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		}
	case pkcs11.CKO_CERTIFICATE:
		attrList = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ISSUER, nil),
			pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, nil),
		}
	}
	attrs, err := p.P11.GetAttributeValue(p.Session, key, attrList)
	if err != nil {
		newErr := fmt.Sprintf("Error getting attributes for object %d: %v", key, err)
		return nil, errors.New(newErr)
	}

	return attrs, nil
}
