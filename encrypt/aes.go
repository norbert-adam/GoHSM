package encrypt

import (
	"errors"
	"fmt"

	"github.com/GoHSM/context"

	"github.com/miekg/pkcs11"
)


func EncryptAes(p *context.AppContext, mech []*pkcs11.Mechanism) error {
	fmt.Println("Hello world!")

	key := p.Selected
	if key == 0 {
		newErr := fmt.Sprint("Error - no key object selected.")
		return errors.New(newErr)
	}

	fmt.Println("Selected key for encryption: ", key)

	return nil
}
