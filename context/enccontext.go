package context

import (
	// "fmt"

	"github.com/miekg/pkcs11"
)

type EncContext struct {
	encKey	pkcs11.ObjectHandle
	data	[]byte
	mech	[]*pkcs11.Mechanism
}
