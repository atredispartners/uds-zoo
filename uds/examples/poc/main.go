package main

import "github.com/atredispartners/uds-zoo/uds/node"

type VulnPoc struct {
	node.Service
	DiagnosticStatus int
	Memory           []byte
}

func (v *VulnPoc) ReadMemoryByAddress([]byte) []byte {
	return []byte{0x63, 0x41, 0x41, 0x41, 0x41, 0x41}
}

func (v *VulnPoc) DiagnosticSessionControl([]byte) []byte {
	v.DiagnosticStatus = 2
	return []byte{0x10, 0x42, 0x42}
}

func (v *VulnPoc) customHandler(payload []byte) []byte {
	if v.DiagnosticStatus == 2 {
		return []byte{0x41, 0x41, 0x41}
	}
	return []byte{0x00, 0x00}
}

func main() {
	poc := &VulnPoc{Service: &node.DefaultService{}}
	//node.DONTREGISTERINSTANCE = true // Remove to register with the node.
	x, err := node.NewInstance(&node.InstanceConfig{
		// if you want to manually specify the listener configuration, uncomment and modify the following line
		//ListenerConfig: node.ListenerConfig{Network: "tcp", Addr: "localhost:9999"},
		ControllerURL: "http://localhost:8888", // change this if your controller is not running locally
		Info: node.InstanceInfo{
			ID:          "0x888",                         // this must be unique to the registered nodes
			Name:        "SillyPoc",                      // short name for the node
			Description: `POC showing how to do things.`, // used for the 'level info'
		},
		Service: poc,
	})
	if err != nil {
		panic(err)
	}
	// whenever you are implementing a handler within your node you need to tell the controller about it
	// this example calls AddHandler on the instance registering the SID 0x41 for the function customHandler
	// in the case you are overriding a function that exists within node/service it will be registered automatically
	x.AddHandler(0x41, poc.customHandler)
	if err := x.Start(); err != nil {
		panic(err)
	}
}
