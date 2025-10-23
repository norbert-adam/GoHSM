package encrypt

import (
	"errors"
	"fmt"

	"github.com/GoHSM/context"

	"github.com/miekg/pkcs11"
)


func EncryptAes(p *context.AppContext, mech []*pkcs11.Mechanism) error {

	iv := make([]byte, 16)
	mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}

	err := p.P11.EncryptInit(p.Session, mech, p.SymKey)
	if err != nil {
		fmt.Println(err)
		return err
	}
	plainText := []byte("This needs to be encryted.")
	fmt.Println("Text to be encrypted: ", string(plainText))
	fmt.Println("Text to be encrypted: ", plainText)

	cipherText, err := p.P11.Encrypt(p.Session, plainText)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer p.P11.EncryptFinal(p.Session)
	fmt.Println("Encrypted text: ", cipherText)
	key := p.SymKey
	if key == 0 {
		newErr := fmt.Sprint("Error - no key object selected.")
		return errors.New(newErr)
	}

	fmt.Println("Selected key for encryption: ", key)

	return nil
}
