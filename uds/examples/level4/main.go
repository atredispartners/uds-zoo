package main

import (
	"bytes"

	"github.com/atredispartners/uds-zoo/uds/node"
	"github.com/atredispartners/uds-zoo/uds/uds"
	"github.com/atredispartners/uds-zoo/uds/utils"
)

type VulnPoc struct {
	node.Service
	DiagnosticStatus    int
	SecurityAccessLevel int
	SeedSent            int
	VIN                 []byte
	Flag                []byte
	Memory              []byte
}

func (v *VulnPoc) SecurityAccess(payload []byte) []byte {
	// handle seed request 0x1
	if bytes.Equal(payload, []byte{0x1}) {
		// return the challenge value
		v.SeedSent = 0x1
		return append([]byte{byte(uds.SecurityAccess + 0x40), payload[0]}, []byte{0xFF, 0xFF, 0xFF, 0xFF}...)
	}

	// handle auth request 0x2
	if payload[0] == byte(0x2) {
		// check a seed was requested first
		if v.SeedSent == 0x0 {
			return []byte{uds.NR, uds.SecurityAccess, uds.RSE}
		}
		// streets closed, find another way home pizza boy
		return []byte{uds.NR, uds.SecurityAccess, uds.IK}
	}
	// default return an error
	return []byte{uds.NR, uds.SecurityAccess, uds.SAD}
}

func (v *VulnPoc) DiagnosticSessionControl(payload []byte) []byte {
	// check if we have proper security access level
	if v.SecurityAccessLevel != 0x2 {
		return []byte{uds.NR, uds.DiagnosticSessionControl, uds.SAD}
	}
	if bytes.Equal(payload, []byte{0x2}) {
		v.DiagnosticStatus = 2
		return []byte{uds.DiagnosticSessionControl + 0x40, 0x02}
	}
	return []byte{uds.NR, uds.DiagnosticSessionControl, uds.SFNS}
}

func (v *VulnPoc) ReadDataByIdentifier(payload []byte) []byte {
	//check that the total payload len fits the dataIdentifier size
	if len(payload)%2 != 0 {
		//invalid data identifier size
		return []byte{uds.NR, uds.ReadDataByIdentifier, uds.IMLOIF}
	}

	// check if the client is attempting to read our protected flag
	if bytes.Equal(payload, []byte{0x13, 0x37}) {
		if v.DiagnosticStatus != 2 {
			// if the sessions is not in diagnostic mode 2, spec states conditions not correct is valid error
			return []byte{uds.NR, uds.ReadDataByIdentifier, uds.CNC}
		}
	}

	// set positive response sid
	var response = []byte{uds.ReadDataByIdentifier + 0x40}
	var dataIdentifier []byte
	for len(payload) != 0 {
		// grab the first identifier from the payload
		dataIdentifier, payload, _ = utils.PopBytes(payload, 2)

		//allow the VIN DID 0xF190
		if bytes.Equal(dataIdentifier, []byte{0xF1, 0x90}) {
			//add the dataIdentifier to the response
			response = append(response, dataIdentifier...)
			//add the dataRecord to the response
			response = append(response, v.VIN...)
		}

		//allow the Flag access since we checked at the start
		if bytes.Equal(dataIdentifier, []byte{0x13, 0x37}) {
			//add the dataIdentifier to the response
			response = append(response, dataIdentifier...)
			//add the dataRecord to the response
			response = append(response, v.Flag...)
		}

	}
	//if we have values to respond with
	if len(response) > 1 {
		return response
	}
	// otherwise request out of range
	return []byte{uds.NR, uds.ReadDataByIdentifier, uds.ROOR}
}

func main() {
	poc := &VulnPoc{Service: &node.DefaultService{}}
	poc.Flag = []byte("i-swear-i-checked-that!")
	poc.DiagnosticStatus = 0x1
	poc.SecurityAccessLevel = 0x0
	poc.SeedSent = 0x0
	poc.VIN = []byte("atredispartners1337")
	//node.DONTREGISTERINSTANCE = true // Remove to register with the node.
	x, err := node.NewInstance(&node.InstanceConfig{
		ControllerURL: "http://localhost:8888",
		Info: node.InstanceInfo{
			ID:   "0x04",
			Name: "Level4",
			Description: `ReadDataByIdentifier Security Bypass.
This level protects the flag DataIdentifier through DiagnosticSession/SecurityAccess flow from before; however, the SecurityAccess function does not contain a password and will always return InvalidKey.
Two DataIdenfiers are available on this level:
VIN  - 0xf190
Flag - 0x1337
The bug in this level is that the ReadDataByIdentifier spec allows multiple DataIdentifiers to be requested at once, returning all requested values.
The check for DiagnosticSession only checks the first submitted DataIdentifier for the flag DataIdentifier before entering the process loop, allowing the attacker to submit an open value (VIN 0xf190) followed by the flag (0x1337).
`,
		},
		Service: poc,
	})
	if err != nil {
		panic(err)
	}
	// override default handler
	x.AddHandler(uds.ReadDataByIdentifier, poc.ReadDataByIdentifier)
	x.AddHandler(uds.SecurityAccess, poc.SecurityAccess)
	if err := x.Start(); err != nil {
		panic(err)
	}
}
