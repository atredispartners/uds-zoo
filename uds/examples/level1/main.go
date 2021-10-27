package main

import (
	"bytes"

	"github.com/atredispartners/uds-zoo/uds/node"
)

type VulnPoc struct {
	node.Service
	DiagnosticStatus int
	Flag             []byte
	Memory           []byte
}

func (v *VulnPoc) ReadMemoryByAddress([]byte) []byte {
	return []byte{0x63, 0x41, 0x41, 0x41, 0x41, 0x41}
}

func (v *VulnPoc) DiagnosticSessionControl([]byte) []byte {
	v.DiagnosticStatus = 2
	return []byte{0x10, 0x42, 0x42}
}

func (v *VulnPoc) ReadDataByIdentifier(payload []byte) []byte {
	// check that the correct Identifier has been requested
	if bytes.Equal(payload, []byte{0x13, 0x37}) {
		return v.Flag
	}
	return []byte{0x7F, 0x22, 0x11}
}

func main() {
	poc := &VulnPoc{Service: &node.DefaultService{}}
	poc.Flag = []byte("babbysfirstflag")

	//node.DONTREGISTERINSTANCE = true // Remove to register with the node.
	x, err := node.NewInstance(&node.InstanceConfig{
		ControllerURL: "http://localhost:8888",
		Info: node.InstanceInfo{
			ID:   "0x01",
			Name: "Level1",
			Description: "Getting your first flag.\nThis level requires the you to execute a ReadDataByIdentifier (0x22) for the flag DataIdentifier (0x1337).\n" +
				"ReadDataByIdentifier allows a client to request one or more data records from the server by their associated data identifier values.\n\n" +
				"An example request for 0x1234:\n 22 1234\n" +
				"An example positive server response:\n 62 1234ABCDEF\n",
		},
		Service: poc,
	})
	if err != nil {
		panic(err)
	}
	x.AddHandler(0x22, poc.ReadDataByIdentifier)
	if err := x.Start(); err != nil {
		panic(err)
	}
}
