package main

import (
	"bytes"

	"github.com/atredispartners/uds-zoo/uds/node"
	"github.com/atredispartners/uds-zoo/uds/uds"
)

type VulnPoc struct {
	node.Service
	DiagnosticStatus int
	Flag             []byte
	Memory           []byte
}

func (v *VulnPoc) DiagnosticSessionControl(payload []byte) []byte {
	if bytes.Equal(payload, []byte{0x2}) {
		v.DiagnosticStatus = 2
		return []byte{0x50, 0x02}
	}
	return []byte{uds.NR, uds.DiagnosticSessionControl, uds.SNS}
}

func (v *VulnPoc) ReadDataByIdentifier(payload []byte) []byte {
	// check that the correct Identifier has been requested
	if bytes.Equal(payload, []byte{0x13, 0x37}) {
		if v.DiagnosticStatus != 2 {
			// if the sessions is not in diagnostic mode 2, service not supported in active session
			return []byte{uds.NR, uds.ReadDataByIdentifier, uds.SNSIAS}
		}
		return append([]byte{byte(uds.ReadDataByIdentifier + 0x40)}, v.Flag...)
	}
	return []byte{uds.NR, uds.ReadDataByIdentifier, uds.CNC}
}

func main() {
	poc := &VulnPoc{Service: &node.DefaultService{}}
	poc.Flag = []byte("d1agn0s1ng-y0ur-sess10n")
	poc.DiagnosticStatus = 0x1
	//node.DONTREGISTERINSTANCE = true // Remove to register with the node.
	x, err := node.NewInstance(&node.InstanceConfig{
		ControllerURL: "http://localhost:8888",
		Info: node.InstanceInfo{
			ID:   "0x02",
			Name: "Level2",
			Description: "Diagnostic Sessions.\n" +
				"This level requires you to switch from the Default session (0x01) to a Programming session (0x02) before access to the flag is allowed.\n" +
				"DiagnosticSessionControl (0x10) allows the client to request a new session context, providing the server the ability to control which services" +
				" or functions are available to client.\n\n" +
				"An example request for a programming session (0x02):\n 10 02\n" +
				"An example positive server response:\n 50 02\n",
		},
		Service: poc,
	})
	if err != nil {
		panic(err)
	}
	// override default handler
	x.AddHandler(uds.ReadDataByIdentifier, poc.ReadDataByIdentifier)
	if err := x.Start(); err != nil {
		panic(err)
	}
}
