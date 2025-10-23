package context

import (
	// "fmt"

	"github.com/miekg/pkcs11"
)

type GenContext struct {
	object	pkcs11.ObjectHandle
}

func (d *GenContext) New(obj pkcs11.ObjectHandle) *GenContext {
	return &GenContext {
		object : obj,
	}
}



