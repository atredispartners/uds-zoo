package main

import (
	"bytes"
	"math/rand"

	"github.com/atredispartners/uds-zoo/uds/node"

	"github.com/atredispartners/uds-zoo/uds/uds"
	"github.com/atredispartners/uds-zoo/uds/utils"
)

type VulnPoc struct {
	node.Service
	DiagnosticStatus    int
	SecurityAccessLevel int
	SeedSent            int
	AuthAttempts        int
	VIN                 []byte
	Flag                []byte
	Memory              []byte
}

func (v *VulnPoc) SecurityAccess(payload []byte) []byte {

	//check to see if we are locked out due to bad attempts
	if v.AuthAttempts >= 3 {
		return []byte{uds.NR, uds.SecurityAccess, uds.ENOA}
	}
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
		password := [][]byte{
			{0x1, 0x1, 0x0, 0x0},
			{0x0, 0x0, 0x1, 0x1},
			{0x0, 0x1, 0x1, 0x0},
			{0x1, 0x0, 0x0, 0x1},
			{0x1, 0x0, 0x1, 0x0},
			{0x1, 0x1, 0x2, 0x2},
			{0x2, 0x1, 0x2, 0x1},
			{0x2, 0x3, 0x2, 0x3},
		}
		//pick a random password from our list
		if bytes.Equal(payload[1:], password[rand.Intn(len(password))]) {
			// set the access level and return positive response
			v.SecurityAccessLevel = 0x2
			return []byte{byte(uds.SecurityAccess + 0x40), payload[0]}
		} else {
			// auth attempt failed, increment the attempt counter and negative response for invalid key
			v.AuthAttempts += 1
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

func (v *VulnPoc) ECUReset(payload []byte) []byte {

	if len(payload) != 1 {
		return []byte{uds.NR, uds.ECUReset, uds.IMLOIF}
	}

	// if reset subfunction is hardReset(0x1) or keyOffOnReset(0x2)
	if payload[0] == uds.HardReset || payload[0] == uds.KeyOffOnReset {
		//reset ecu state
		v.DiagnosticStatus = 0x1
		v.SecurityAccessLevel = 0x0
		v.SeedSent = 0x0
		v.AuthAttempts = 0x0
		v.VIN = []byte("atredispartners1337")
		return []byte{uds.ECUReset + 0x40, payload[0]}

	}
	return []byte{uds.NR, uds.ECUReset, uds.SFNS}
}

func (v *VulnPoc) ReadDataByIdentifier(payload []byte) []byte {
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

		//allow the VIN DID 0xF190
		if bytes.Equal(dataIdentifier, []byte{0xF1, 0x90}) {
			//add the dataIdentifier to the response
			response = append(response, dataIdentifier...)
			//add the dataRecord to the response
			response = append(response, v.VIN...)
		}

		//allow the Flag access since we checked at the start
		if bytes.Equal(dataIdentifier, []byte{0x13, 0x37}) {
			// SECURITY FIX.
			if v.DiagnosticStatus != 2 {
				// if the sessions is not in diagnostic mode 2, spec states conditions not correct is valid error
				return []byte{uds.NR, uds.ReadDataByIdentifier, uds.CNC}
			}
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
	poc.Flag = []byte("did-you-turn-it-on-and-off-again")
	poc.DiagnosticStatus = 0x1
	poc.SecurityAccessLevel = 0x0
	poc.SeedSent = 0x0
	poc.AuthAttempts = 0x0
	poc.VIN = []byte("atredispartners1337")
	//node.DONTREGISTERINSTANCE = true // Remove to register with the server.
	x, err := node.NewInstance(&node.InstanceConfig{
		ControllerURL: "http://localhost:8888",
		Info: node.InstanceInfo{
			ID:   "0x05",
			Name: "Level5",
			Description: `Security Access Lockout
This level requires the user to unlock Security Access using seed 0x01 before the DiagnosticSession can be started, and 
the flag can be retrieved using ReadDataByIdentifier. The previous SecurityAccess level used a hardcoded key, this level
picks a random key from the following list:

		{0x1, 0x1, 0x0, 0x0},
		{0x0, 0x0, 0x1, 0x1},
		{0x0, 0x1, 0x1, 0x0},
		{0x1, 0x0, 0x0, 0x1},
		{0x1, 0x0, 0x1, 0x0},
		{0x1, 0x1, 0x2, 0x2},
		{0x2, 0x1, 0x2, 0x1},
		{0x2, 0x3, 0x2, 0x3},


After 3 bad attempts the server will lock, preventing further guesses. The user can get around the lock by requesting
an EcuReset (0x11) and continue guessing until they receive a positive response. Unlock again allows the user to access
DiagnosticSession 0x02 and ReadDataIdentifier the flag 0x1337.`,
		},
		Service: poc,
	})
	if err != nil {
		panic(err)
	}
	// override default handler
	x.AddHandler(uds.ReadDataByIdentifier, poc.ReadDataByIdentifier)
	x.AddHandler(uds.SecurityAccess, poc.SecurityAccess)
	x.AddHandler(uds.ECUReset, poc.ECUReset)
	if err := x.Start(); err != nil {
		panic(err)
	}
}
