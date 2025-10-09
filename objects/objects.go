package objects

import (
	"fmt"
	"errors"
	"encoding/binary"

	"github.com/GoHSM/utils"

	"github.com/miekg/pkcs11"
)


func ListObjects(p *pkcs11.Ctx, session pkcs11.SessionHandle, searchOption string) {

	foundObjs := []pkcs11.ObjectHandle{}

	err := p.FindObjectsInit(session, []*pkcs11.Attribute{})
	if err != nil {
		fmt.Println("Error initializing FindObjects: ", err)
		return
	}
	defer p.FindObjectsFinal(session)

	for {
		objs, _, err := p.FindObjects(session, 1)
		if err != nil {
			fmt.Println("Error finding objects.")
			return
		}

		if len(objs) == 0 {
			break
		}

		obj := objs[0]
		attr, err := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			return
		}

		switch searchOption {
		case "listObjs":
			foundObjs = append(foundObjs, obj)
		case "listKeys":
			a := attr[0]
			aVal := binary.LittleEndian.Uint32(a.Value[:4])
			if aVal == pkcs11.CKO_SECRET_KEY || aVal == pkcs11.CKO_PUBLIC_KEY || aVal == pkcs11.CKO_PRIVATE_KEY {
				foundObjs = append(foundObjs, obj)
			}
		case "listCerts":
			a := attr[0]
			aVal := binary.LittleEndian.Uint32(a.Value[:4])
			if aVal == pkcs11.CKO_CERTIFICATE {
				foundObjs = append(foundObjs, obj)
			}
		}	
	}

	fmt.Println("found: ", foundObjs)

	for _, obj := range foundObjs {
		attr, err := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		})
		if err != nil {
			return
		}

		attrs, err := getKeyAttributes(p, session, obj, attr[0])
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
		fmt.Println("Secret key")
		attrList = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
		}
	case pkcs11.CKO_PUBLIC_KEY:
		fmt.Println("Public key")
		attrList = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
		}
	case pkcs11.CKO_PRIVATE_KEY:
		fmt.Println("Private key")
		attrList = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		}
	}
	attrs, err := p.GetAttributeValue(session, key, attrList)
	if err != nil {
		newErr := fmt.Sprintf("Error getting attributes for object %d: %v", key, err)
		return nil, errors.New(newErr)
	}

	return attrs, nil
}
