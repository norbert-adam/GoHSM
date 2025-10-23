package objects

import (
	"fmt"
	"errors"
	"encoding/binary"

	"github.com/GoHSM/context"

	"github.com/miekg/pkcs11"
)

func listAttributes(p *context.AppContext, objList []pkcs11.ObjectHandle) error {
	for _, obj := range objList {
		objectType, err := GetObjectType(p, obj)
		if err != nil {
			return err
		}

		attrTemplate := getAttributeTemplate("medium", objectType)

		attrs, err := p.P11.GetAttributeValue(p.Session, obj, attrTemplate)
		if err != nil {
			newErr := fmt.Sprintf("Error getting attributes for object %d: %v", obj, err)
			return errors.New(newErr)
		}

		fmt.Printf("Object handle %v:\n", obj)
		for _, a := range attrs {
			fmt.Printf("\t%v\n", AttrToString(a))
		}
	}
	
	return nil
}


func GetKeyType(p *context.AppContext, object pkcs11.ObjectHandle) (uint32, error) {
	attrs, err := p.P11.GetAttributeValue(p.Session, object, []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
    })
	if err != nil {
		newErr := fmt.Sprint("Error getting object type: ", err)
		return 0, errors.New(newErr)
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
        return 0, fmt.Errorf("empty CKA_CLASS value")
    }

	keyType := binary.LittleEndian.Uint32(attrs[0].Value[:4])
	return keyType, nil
}

func GetObjectType(p *context.AppContext, object pkcs11.ObjectHandle) (uint32, error) {
	attrs, err := p.P11.GetAttributeValue(p.Session, object, []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
    })
	if err != nil {
		newErr := fmt.Sprint("Error getting object type: ", err)
		return 0, errors.New(newErr)
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
        return 0, fmt.Errorf("empty CKA_CLASS value")
    }

	class := binary.LittleEndian.Uint32(attrs[0].Value[:4])
	return class, nil
}


func getAttributeTemplate(templateType string, objectType uint32) []*pkcs11.Attribute {
	switch templateType {
	case "short":
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		}
	case "medium":
		switch objectType {
		case pkcs11.CKO_SECRET_KEY:
			return []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
			}
		case pkcs11.CKO_PUBLIC_KEY:
			return []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
			}
		case pkcs11.CKO_PRIVATE_KEY:
			return []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			}
		case pkcs11.CKO_CERTIFICATE:
			return []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil),
				pkcs11.NewAttribute(pkcs11.CKA_ISSUER, nil),
				pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, nil),
			}
		}
	case "long":
		return nil
	}
	return nil
}
