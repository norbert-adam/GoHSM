package objects

import (
	"fmt"
	"errors"

	"github.com/GoHSM/context"

	"github.com/miekg/pkcs11"
)

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

		objectType, err := getObjectType(p, objs[0])
		if err != nil {
			return nil, err
		}

		switch searchOption {
		case "All":
			foundObjs = append(foundObjs, objs[0])
		case "Keys":
			if objectType == pkcs11.CKO_SECRET_KEY || objectType == pkcs11.CKO_PUBLIC_KEY || objectType == pkcs11.CKO_PRIVATE_KEY {
				foundObjs = append(foundObjs, objs[0])
			}
		case "Certs":
			if objectType == pkcs11.CKO_CERTIFICATE {
				foundObjs = append(foundObjs, objs[0])
			}
		}	
	}
	
	return foundObjs, nil
}
