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



func GenerateAES(p *pkcs11.Ctx, session pkcs11.SessionHandle) (pkcs11.ObjectHandle, error){
	var keySize int	
	var keyLabel string
	tok := "N"
	var keyToken bool
	fmt.Println("AES generation called.")
	fmt.Println("Specify the attributes of the key:")
	fmt.Printf("\tAES key size in bits (128-256):\t")
	fmt.Scan(&keySize)
	keySize = keySize / 8
	fmt.Printf("\tKey label for the key:\t")
	fmt.Scan(&keyLabel)
	fmt.Printf("\tShould the key be stored on the HSM (Y/N)?\t")
	fmt.Scan(&tok)
	if tok == "Y" || tok == "y" {
		keyToken = true
	} else {
		keyToken = false
	}

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
        pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keySize), // 256 bits
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
        pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, keyToken),
	}

	aesKey, err := p.GenerateKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, keyTemplate)
	if err != nil {
		newError := fmt.Sprint("Error in AES key generation: ", err)
		return 0, errors.New(newError)
	}
	return aesKey, nil
}

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
