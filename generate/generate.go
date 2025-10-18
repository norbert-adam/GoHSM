package generate

import (
	"fmt"
	"errors"

	"github.com/GoHSM/context"
	// "github.com/GoHSM/objects"

	"github.com/miekg/pkcs11"
)


func DeleteObject(p *context.AppContext, obj pkcs11.ObjectHandle) error {
	err := p.P11.DestroyObject(p.Session, obj)
	if err != nil {
		newErr := fmt.Sprint("Error destroying object: ", err)
		return errors.New(newErr)
	}
	return nil
}


func GenDetails() (int, error) {
	var selection int
	fmt.Println("Select the type of key you want to generate:")
	fmt.Println("\t1. AES")
	fmt.Println("\t2. RSA")
	_, err := fmt.Scan(&selection)
	if err != nil {
		return 0, err
	}
	return selection, nil
}


func GenerateRSA(p *pkcs11.Ctx, session pkcs11.SessionHandle) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	fmt.Println("RSA generation called.")

	var keySize int	
	var keyLabel string
	tok := "N"
	var keyToken bool

	fmt.Println("Specify the attributes of the key:")
	fmt.Printf("\tRSA key size in bits (1024-4096):\t")
	fmt.Scan(&keySize)
	fmt.Printf("\tKey label for the key:\t")
	fmt.Scan(&keyLabel)
	keyLabelPub := fmt.Sprintf("%sPub", keyLabel)
	keyLabelPriv := fmt.Sprintf("%sPriv", keyLabel)
	fmt.Printf("\tShould the key be stored on the HSM (Y/N)?\t")
	fmt.Scan(&tok)
	if tok == "Y" || tok == "y" {
		keyToken = true
	} else {
		keyToken = false
	}

	// // Example: generate a key pair
	pubTempl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabelPub),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keySize),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
	}

	privTempl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabelPriv),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, keyToken),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
	}

	pub, priv, err := p.GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, pubTempl, privTempl,)
	if err != nil {
		newError := fmt.Sprint("Error in RSA keypair generation: ", err)
		return 0, 0, errors.New(newError)
	}

	return pub, priv, nil
}


func GenerateECC(p *pkcs11.Ctx, session pkcs11.SessionHandle) {
	oidP256 := []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07} // 1.2.840.10045.3.1.7

	pubTempl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyECCKey_pub"),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oidP256),
	}

	privTempl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyECCKey_priv"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}

	pub, priv, err := p.GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, pubTempl, privTempl,)
	if err != nil {
		fmt.Println("Error in ECC key pair generation: ", err)
		// newError := fmt.Sprint("Error in ECC keypair generation: ", err)
		// return 0, 0, errors.New(newError)
		return
	}

	fmt.Println("ECC Key Pair Generation successful!")
	fmt.Println("PubKey: ", pub)
	fmt.Println("PrivKey: ", priv)
}

