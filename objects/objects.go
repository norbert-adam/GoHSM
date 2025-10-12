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
	options := map[int]string{
		1: "All",
		2: "Key",
		3: "Cert",
	}

	fmt.Printf("Select the type of option you want to list:\n")
	fmt.Printf("\t1. All Objects\n")
	fmt.Printf("\t2. Keys\n")
	fmt.Printf("\t3. Certificates\n")

	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Incorrect input: %v", err)
		return nil, errors.New(newErr)
	}
	if selection < 1 || selection > 5 {
		return nil, errors.New("incorrect input - selected option must be between 1 and 5")
	}

	switch selection {
	case 1:
		ListObjects(p, options[selection])
	}

	return p, nil
}


func ListObjects(p *context.AppContext, searchOption string) {

	ctx := p.P11
	session := p.Session
	foundObjs := []pkcs11.ObjectHandle{}

	err := ctx.FindObjectsInit(session, []*pkcs11.Attribute{})
	if err != nil {
		fmt.Println("Error initializing FindObjects: ", err)
		return
	}
	defer ctx.FindObjectsFinal(session)

	for {
		objs, _, err := ctx.FindObjects(session, 1)
		if err != nil {
			fmt.Println("Error finding objects.")
			return
		}

		if len(objs) == 0 {
			break
		}

		obj := objs[0]
		attr, err := ctx.GetAttributeValue(session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			return
		}

		switch searchOption {
		case "All":
			foundObjs = append(foundObjs, obj)
		case "Keys":
			a := attr[0]
			aVal := binary.LittleEndian.Uint32(a.Value[:4])
			if aVal == pkcs11.CKO_SECRET_KEY || aVal == pkcs11.CKO_PUBLIC_KEY || aVal == pkcs11.CKO_PRIVATE_KEY {
				foundObjs = append(foundObjs, obj)
			}
		case "Certs":
			a := attr[0]
			aVal := binary.LittleEndian.Uint32(a.Value[:4])
			if aVal == pkcs11.CKO_CERTIFICATE {
				foundObjs = append(foundObjs, obj)
			}
		}	
	}

	for _, obj := range foundObjs {
		attr, err := ctx.GetAttributeValue(session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			return
		}

		attrs, err := getKeyAttributes(ctx, session, obj, attr[0])
		if err != nil {
			fmt.Printf("Error reading object %v: %v\n", obj, err)
			return
		}

		fmt.Printf("Object handle %v:\n", obj)
		for _, a := range attrs {
			fmt.Printf("\t%v\n", utils.AttrToString(a))
		}
	}
}


func getKeyAttributes(p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, keyType *pkcs11.Attribute) ([]*pkcs11.Attribute, error ){
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
	attrs, err := p.GetAttributeValue(session, key, attrList)
	if err != nil {
		newErr := fmt.Sprintf("Error getting attributes for object %d: %v", key, err)
		return nil, errors.New(newErr)
	}

	return attrs, nil
}
