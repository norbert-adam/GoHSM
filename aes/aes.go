package aes

import (
	"errors"
	"fmt"
	"encoding/hex"

	"github.com/GoHSM/generate"
	"github.com/miekg/pkcs11"
)


// TODO: HANDLING KEYS
// If generating keys:
	// What for? Encr/Decr or Wrap/Unwrap
// If using keys that already exist
	// Get the attributes of the key
	// Check whether it could be used for the operation


func WrapAES(p *pkcs11.Ctx, session pkcs11.SessionHandle, kek pkcs11.ObjectHandle) {

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}	

	_, priv, err := generate.GenerateRSA(p, session)
	if err != nil {
		fmt.Println("Error rsa gen.")
		return
	}

	wrappedKey, err := p.WrapKey(session, mech, kek, priv)
	if err != nil {
		fmt.Println("Error wrapping key.")
	}
	fmt.Printf("Wrapped private key (%d bytes): %s\n", len(wrappedKey), hex.EncodeToString(wrappedKey))

	unwrappedLabel := "Unwrapped_RSA_Priv"
	unwrappedTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, unwrappedLabel),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		// whether this unwrapped key is sensitive/extractable is up to you:
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	}

	origKey, err := p.UnwrapKey(session, mech, kek, wrappedKey, unwrappedTemplate)
	if err != nil {
		fmt.Println("error unwrapping")
		return
	}
	fmt.Println("Success unwrapping: ", origKey)

}
