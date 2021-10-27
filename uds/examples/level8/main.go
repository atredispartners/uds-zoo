package main

import (
	"bytes"
	"crypto/rand"

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

const (
	DIAG_STATUS = 0x10
	VIN         = 0x20
	// ACCESS_LEVEL pack together to use less memory
	ACCESS_LEVEL  = 0x50
	SEED_SENT     = 0x51
	AUTH_ATTEMPTS = 0x52
	CURRENT_SEED  = 0x53
	XOR_KEY       = 0x5C
	SEED_LEN      = 0x8
)

func (v *VulnPoc) SecurityAccess(payload []byte) []byte {

	//check to see if we are locked out due to bad attempts
	if v.Memory[AUTH_ATTEMPTS] >= 3 {
		return []byte{uds.NR, uds.SecurityAccess, uds.ENOA}
	}
	// handle seed request 0x1
	if bytes.Equal(payload, []byte{0x1}) {
		// return the challenge value
		v.Memory[SEED_SENT] = 0x1
		// generate seed and xor key
		seed := make([]byte, 8)
		xorkey := make([]byte, 8)
		rand.Read(seed)
		rand.Read(xorkey)
		utils.WriteMemory(&v.Memory, seed, CURRENT_SEED)
		utils.WriteMemory(&v.Memory, xorkey, XOR_KEY)
		return append([]byte{byte(uds.SecurityAccess + 0x40), payload[0]}, seed...)
	}

	// handle auth request 0x2
	if payload[0] == byte(0x2) {
		// check a seed was requested first
		if v.Memory[SEED_SENT] == 0x0 {
			return []byte{uds.NR, uds.SecurityAccess, uds.RSE}
		}
		// check the auth attempt
		// key == XorBytes(seed,xorkey)
		currentSeed, _ := utils.ReadMemory(v.Memory, CURRENT_SEED, SEED_LEN)
		currentKey, _ := utils.ReadMemory(v.Memory, XOR_KEY, SEED_LEN)
		currentPass, _ := utils.XorBytes(currentSeed, currentKey)
		if bytes.Equal(payload[1:], currentPass) {
			// set the access level and return positive response
			v.Memory[ACCESS_LEVEL] = 0x2
			return []byte{byte(uds.SecurityAccess + 0x40), payload[0]}
		} else {
			// auth attempt failed, increment the attempt counter and negative response for invalid key
			v.Memory[AUTH_ATTEMPTS] += 1
			return []byte{uds.NR, uds.SecurityAccess, uds.IK}
		}
	}
	// default return an error
	return []byte{uds.NR, uds.SecurityAccess, uds.SAD}
}

func (v *VulnPoc) DiagnosticSessionControl(payload []byte) []byte {
	// check if we have proper security access level
	if v.Memory[ACCESS_LEVEL] != 0x2 {
		return []byte{uds.NR, uds.DiagnosticSessionControl, uds.SAD}
	}
	if bytes.Equal(payload, []byte{0x2}) {
		v.Memory[DIAG_STATUS] = 2
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
		v.Memory[DIAG_STATUS] = 0x1
		v.Memory[ACCESS_LEVEL] = 0x0
		v.Memory[SEED_SENT] = 0x0
		v.Memory[AUTH_ATTEMPTS] = 0x0
		// retain our auth attempts to fix lockout bypass
		//v.AuthAttempts = 0x0
		return []byte{uds.ECUReset + 0x40, payload[0]}

	}
	return []byte{uds.NR, uds.ECUReset, uds.SFNS}
}

func (v *VulnPoc) WriteMemoryByAddress(payload []byte) []byte {
	/*
		WriteMemoryByAddress payload layout
		[addressAndLengthFormatIdentifier][memoryAddress][memorySize][dataRecord]
												[sizeLen] [addrLen]
		addressAndLengthFormatIdentifier: 00-FF   0000      0000
			encoded subvalues: memorySizeLength = (addressAndLengthFormatIdentifier & 0xf0) >> 4
		                       addressSizeLength = addressAndLengthFormatIdentifier & 0xf

	*/
	addressFormat := payload[0]
	addressLength := int(addressFormat & 0xf)
	sizeLength := int(addressFormat&0xf0) >> 4
	if sizeLength == 0 || addressLength == 0 {
		return []byte{uds.NR, uds.ReadMemoryByAddress, uds.ROOR}
	}
	//use PopBytes to split the memoryAddress from the full payload
	memoryAddress, sizeAndData, err := utils.PopBytes(payload[1:], addressLength)
	if err != nil {
		return []byte{uds.NR, uds.WriteMemoryByAddress, uds.ROOR}
	}
	// use PopBytes again to split memorySize from dataRecord
	memorySize, dataRecord, err := utils.PopBytes(sizeAndData, sizeLength)
	if err != nil {
		return []byte{uds.NR, uds.WriteMemoryByAddress, uds.ROOR}
	}

	addr, err := utils.BytesToUInt(memoryAddress)
	if err != nil {
		return []byte{uds.NR, uds.ReadMemoryByAddress, uds.ROOR}

	}
	mSize, err := utils.BytesToUInt(memorySize)
	if err != nil {
		return []byte{uds.NR, uds.WriteMemoryByAddress, uds.ROOR}
	}

	//check that length of dataRecord matches our input size
	if int(mSize) != len(dataRecord) {
		//return []byte{uds.NR, uds.WriteMemoryByAddress, uds.ROOR}
		return []byte{uds.NR, uds.WriteMemoryByAddress, 0xFF}
	}

	//check to make sure request cannot access from ACCESS_LEVEL (0x50) to XOR_KEY (0x78)
	if (addr >= ACCESS_LEVEL && addr <= (XOR_KEY+SEED_LEN)) || (addr <= ACCESS_LEVEL && (addr+mSize) > ACCESS_LEVEL) {
		//return security access denied
		return []byte{uds.NR, uds.WriteMemoryByAddress, uds.SAD}
	}

	err = utils.WriteMemory(&v.Memory, dataRecord, int(addr))
	if err != nil {
		return []byte{uds.NR, uds.WriteMemoryByAddress, uds.ROOR}
	}
	// positive response [WriteMemoryByAddress][addressAndLengthFormat][MemoryAddress][MemorySize]
	retPayload := append([]byte{addressFormat}, memoryAddress...)
	retPayload = append(retPayload, memorySize...)
	return append([]byte{byte(uds.WriteMemoryByAddress + 0x40)}, retPayload...)

}

func (v *VulnPoc) ReadMemoryByAddress(payload []byte) []byte {
	/*
		ReadMemoryByAddress payload layout
		[addressAndLengthFormatIdentifier][memoryAddress][memorySize]
												[sizeLen] [addrLen]
		addressAndLengthFormatIdentifier: 00-FF   0000      0000
			encoded subvalues: memorySizeLength = (addressAndLengthFormatIdentifier & 0xf0) >> 4
		                       addressSizeLength = addressAndLengthFormatIdentifier & 0xf

	*/
	addressFormat := payload[0]
	addressLength := int(addressFormat & 0xf)
	sizeLength := int(addressFormat&0xf0) >> 4
	if sizeLength == 0 || addressLength == 0 {
		return []byte{uds.NR, uds.ReadMemoryByAddress, uds.ROOR}
	}
	//use PopBytes to split the rest of the payload up based on format specifiers
	memoryAddress, memorySize, err := utils.PopBytes(payload[1:], addressLength)
	if err != nil {
		return []byte{uds.NR, uds.ReadMemoryByAddress, uds.ROOR}
	}

	addr, err := utils.BytesToUInt(memoryAddress)
	if err != nil {
		return []byte{uds.NR, uds.ReadMemoryByAddress, uds.ROOR}

	}
	mSize, err := utils.BytesToUInt(memorySize)
	if err != nil {
		return []byte{uds.NR, uds.ReadMemoryByAddress, uds.ROOR}
	}

	//check to make sure request cannot access the seed + key
	if (addr >= CURRENT_SEED && addr <= (XOR_KEY+SEED_LEN)) || (addr < CURRENT_SEED && (addr+mSize) > CURRENT_SEED) {
		//return security access denied
		return []byte{uds.NR, uds.ReadMemoryByAddress, uds.SAD}
	}

	mem, err := utils.ReadMemory(v.Memory, int(addr), int(mSize))
	if err != nil {
		return []byte{uds.NR, uds.ReadMemoryByAddress, uds.ROOR}
	}
	return append([]byte{byte(uds.ReadMemoryByAddress + 0x40)}, mem...)

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
			vin, _ := utils.ReadMemoryStr(v.Memory, VIN)
			response = append(response, vin...)
		}

		//allow the Flag access since we checked at the start
		if bytes.Equal(dataIdentifier, []byte{0x13, 0x37}) {
			// ensure diag is 0x2 and access level is 0x2 - catch cases where someone writes their own diag status
			if v.Memory[DIAG_STATUS] != 0x02 || v.Memory[ACCESS_LEVEL] != 0x2 {
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
	poc.Flag = []byte("im-still-not-conVINced")
	//initialize array and set values
	poc.Memory = make([]byte, 0x100)
	poc.Memory[DIAG_STATUS] = 0x1
	poc.Memory[ACCESS_LEVEL] = 0x1
	poc.Memory[SEED_SENT] = 0x0
	poc.Memory[AUTH_ATTEMPTS] = 0x0
	poc.Memory[DIAG_STATUS] = 0x1
	poc.Memory[SEED_SENT] = 0x0
	poc.Memory[AUTH_ATTEMPTS] = 0x0
	utils.WriteMemory(&poc.Memory, []byte("atredispartners1337"), VIN)
	//node.DONTREGISTERINSTANCE = true // Remove to register with the server.
	x, err := node.NewInstance(&node.InstanceConfig{
		ControllerURL: "http://localhost:8888",
		Info: node.InstanceInfo{
			ID:   "0x08",
			Name: "Level8",
			Description: `WriteMemoryByAddress (0x3d)
This level is the same as level 7 - the following security rules have been implemented around sensitive memory:
Write Prohibited - 0x50 - 0x64
Read Prohibited - 0x53 - 0x64
// ACCESS_LEVEL pack together to use less memory
ACCESS_LEVEL  = 0x50
SEED_SENT     = 0x51
AUTH_ATTEMPTS = 0x52
CURRENT_SEED  = 0x53
XOR_KEY       = 0x5C

Example WriteMemoryByAddress Message:
3d 11 00 01 ff
Message Definition:
WriteMemoryByAddress - 0x3d
AddressAndLengthFormat - 0x11 - high nibble is length of memory size, low is length of Address
MemoryAddress - 0x00 - memory address to write to
MemorySize - 0x01 - size of memory write
DataRecord - 0xff

Positive Response:
7d 110001
AddressAndLengthFormat - 0x11 - high nibble is length of memory size, low is length of Address
MemoryAddress - 0x00 - memory address to written to
MemorySize - 0x01 - size of memory written`,
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
	x.AddHandler(uds.ReadMemoryByAddress, poc.ReadMemoryByAddress)
	x.AddHandler(uds.WriteMemoryByAddress, poc.WriteMemoryByAddress)
	if err := x.Start(); err != nil {
		panic(err)
	}
}
