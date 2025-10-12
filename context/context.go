package context

import (
	"fmt"
	"errors"
	
	"github.com/miekg/pkcs11"
)


type AppContext struct {
	P11			*pkcs11.Ctx
	Session		pkcs11.SessionHandle
	Selected	pkcs11.ObjectHandle
}

 
func InitializeContext() (*AppContext, error) {

	p:= pkcs11.New("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
	err := p.Initialize()
	if err != nil {
		newError := fmt.Sprint("Error loading pkcs11 module: ", err)
		return nil, errors.New(newError)
	}

	slots, err := processSlots(p)
	if err != nil {
		return nil, err
	}

	slot, err := selectSlot(slots)
	if err != nil {
		return nil, err
	}

	session, err := sessionLogin(p, slot)
	if err != nil {
		return nil, err
	}

	ap := &AppContext{
		P11: p,
		Session: session,
	}
	return ap, nil
}


func processSlots(p *pkcs11.Ctx) ([]uint, error) {

	slots, err := p.GetSlotList(true)
	if err != nil {
		newErr := fmt.Sprintf("Error listing slots: %s\n", err)
		return nil, errors.New(newErr)
	}

	fmt.Println("Available slots:")
	for i, slot := range slots {
		tInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			newErr := fmt.Sprintf("Error loading token info: %s\n", err)
			return nil, errors.New(newErr)
		}
		var label string
		if tInfo.Label == "" {
			label = "N/A"
		} else {
			label = tInfo.Label
		}
		fmt.Printf("\t%d. Slot: %s (%d)\n", i, label, slot)
	}
	return slots, nil
}

func selectSlot(slots []uint) (uint, error) {

	fmt.Printf("Select slot: ")
	var selection int
	_, err := fmt.Scan(&selection)
	if err != nil {
		newErr := fmt.Sprintf("Invalid input for slot selection: %s\n", err)
		return 0, errors.New(newErr)
	}

	if selection > len(slots)-1 || selection < 0 {
		return 0, errors.New("Invalid input for slot selection")
	}

	slot := slots[selection]

	return slot, nil
}

func sessionLogin(p *pkcs11.Ctx, slot uint) (pkcs11.SessionHandle, error){
	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		newErr := fmt.Sprint("Error opening session to slot %d: %s\n", slot, err)
		return 0, errors.New(newErr)
	}

	password, err := getPassword()
	if err != nil {
		return 0, err
	}

	err = p.Login(session, pkcs11.CKU_USER, password)
	if err != nil {
		newErr := fmt.Sprintf("Error logging in to session %d: %v\n", session, err)
		return 0, errors.New(newErr)
	}

	return session, nil
}

func getPassword() (string, error) {
	fmt.Printf("Being login process - please provide password: ")
	var pwd string
	_, err := fmt.Scan(&pwd)
	if err != nil {
		newErr := fmt.Sprintf("Invalid password provided: %s\n", err)
		return "", errors.New(newErr)
	}

	return pwd, nil
}
