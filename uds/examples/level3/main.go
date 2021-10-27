package main

import (
	"bytes"

	"github.com/atredispartners/uds-zoo/uds/node"
	"github.com/atredispartners/uds-zoo/uds/uds"
)

type VulnPoc struct {
	node.Service
	DiagnosticStatus    int
	SecurityAccessLevel int
	SeedSent            int
	Flag                []byte
	Memory              []byte
}

func (v *VulnPoc) SecurityAccess(payload []byte) []byte {
	// handle seed request 0x1
	if bytes.Equal(payload, []byte{0x1}) {
		// return the challenge value
		v.SeedSent = 0x1
		return append([]byte{byte(uds.SecurityAccess + 0x40), payload[0]}, []byte{0x41, 0x41, 0x41, 0x41, 0x41}...)
	}

	// handle auth request 0x2
	if payload[0] == byte(0x2) {
		// check a seed was requested first
		if v.SeedSent == 0x0 {
			return []byte{uds.NR, uds.SecurityAccess, uds.RSE}
		}
		// check the auth attempt
		password := []byte{0x1, 0x2, 0x3, 0x4}
		if bytes.Equal(payload[1:], password) {
			// set the access level and return positive response
			v.SecurityAccessLevel = 0x2
			return []byte{byte(uds.SecurityAccess + 0x40), payload[0]}
		} else {
			// auth attempt failed, negative response for invalid key
			return []byte{uds.NR, uds.SecurityAccess, uds.IK}
		}
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
	// check that the correct Identifier has been requested
	if bytes.Equal(payload, []byte{0x13, 0x37}) {
		if v.DiagnosticStatus != 2 {
			// if the sessions is not in diagnostic mode 2, spec states conditions not correct is valid error
			return []byte{uds.NR, uds.ReadDataByIdentifier, uds.CNC}
		}
		return append([]byte{byte(uds.ReadDataByIdentifier + 0x40)}, v.Flag...)
	}
	// otherwise request out of range
	return []byte{uds.NR, uds.ReadDataByIdentifier, uds.ROOR}
}

func main() {
	poc := &VulnPoc{Service: &node.DefaultService{}}
	poc.Flag = []byte("babbysfirstunlock")
	poc.DiagnosticStatus = 0x1
	poc.SecurityAccessLevel = 0x0
	poc.SeedSent = 0x0
	//node.DONTREGISTERINSTANCE = true // Remove to register with the node.
	x, err := node.NewInstance(&node.InstanceConfig{
		ControllerURL: "http://localhost:8888",
		Info: node.InstanceInfo{
			ID:   "0x03",
			Name: "Level3",
			Description: "Security Access Control Example.\n" +
				"This level requires you to unlock Security Access using seed 0x01 before the DiagnosticSession can be" +
				"started and the flag can be retrieved using ReadDataByIdentifier.\n" +
				"The password for the SecurityAccess is hardcoded to `01020304`.\n" +
				"Example Security Access Control Process:\n" +
				"Request seed 0x01: 27 01\n" +
				"Submit computed key: 27 02 6C65746D65696E",
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
