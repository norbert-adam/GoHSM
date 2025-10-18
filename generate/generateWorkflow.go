package generate

import (
	"fmt"

	"github.com/GoHSM/objects"
	"github.com/GoHSM/userif"
	"github.com/GoHSM/context"
	
	"github.com/miekg/pkcs11"
)


func GenDelWorkflow(p *context.AppContext, task string) (pkcs11.ObjectHandle, error) {

	switch task {
	case "Delete":
		_, err := DeleteWorkflow(p)
		if err != nil {
			return 0, err
		}
	case "Generate":
		GenerateWorkflow()
	}
	return 0, nil
}


func DeleteWorkflow(p *context.AppContext) (pkcs11.ObjectHandle, error) {
	userif.ClearTerminal()
	objs, err := objects.ListObjects(p, "All")
	if err != nil {
		return 0, err
	}
	obj, err := objects.SelectObject(p, objs)
	if err != nil {
		return 0, err
	}
	err = DeleteObject(p, obj)
	if err != nil {
		return 0, err
	}
	
	fmt.Printf("Object %d successfully deleted!\n", obj)
	return 0, nil
}


func GenerateWorkflow() {
	fmt.Println("Generate in Generate Workflow")
}
