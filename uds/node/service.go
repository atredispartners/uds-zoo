package node

import (
	"github.com/atredispartners/uds-zoo/uds/uds"
	"github.com/atredispartners/uds-zoo/uds/utils"
)

// Service is an interface for implementing all UDS services.
// See https://en.wikipedia.org/wiki/Unified_Diagnostic_Services for details.
type Service interface {
	ReadMemoryByAddress([]byte) []byte      // 0x23
	DiagnosticSessionControl([]byte) []byte // 0x10
	ReadDataByIdentifier([]byte) []byte     // 0x22
	NotImplemented(byte) []byte             // catch all
}

// DefaultService includes an implementation of Services and is meant to be used
// with composition for your Go struct.
// Example defining a new struct that uses composition with the DefaultService
//
// type ExampleService struct {
// 		node.Service
// }
//
// e := ExampleService{Service: &node.DefaultService{}}
//
//
type DefaultService struct {
}

// TODO: Implement the remaining services
func (d *DefaultService) ReadMemoryByAddress([]byte) []byte {
	return []byte{0x23, 0x00}
}

func (d *DefaultService) DiagnosticSessionControl([]byte) []byte {
	return []byte{0x10, 0x00}
}

func (d *DefaultService) ReadDataByIdentifier(payload []byte) []byte {
	//check that the total payload len fits the dataIdentifier size
	if len(payload)%2 != 0 {
		//invalid data identifier size
		return []byte{uds.NR, uds.ReadDataByIdentifier, uds.IMLOIF}
	}
	// set positive response sid
	var response = []byte{uds.ReadDataByIdentifier + 0x40}
	var dataIdentifier []byte
	for len(payload) != 0 {
		// grab the first identifier from the payload
		dataIdentifier, payload, _ = utils.PopBytes(payload, 2)
		//add the dataIdentifier to the response
		response = append(response, dataIdentifier...)

		//TODO: Implement dataIdentifier dataRecord code, hardcoded value as an example
		//dataRecord := getDataRecord(dataIdentifier)
		dataRecord := []byte{0xff, 0xff, 0xff}

		//add the dataRecord to the response
		response = append(response, dataRecord...)
	}

	return response
}

// NotImplemented: Service not implemented handler to catch all unknown services
// that have not been implemented. Returns standard UDS error Service Not Supported (SNS).
func (d *DefaultService) NotImplemented(sid byte) []byte {
	return []byte{sid, uds.SNS}
}
