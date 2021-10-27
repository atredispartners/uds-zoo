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
	DiagnosticStatus       int
	SecurityAccessLevel    int
	SeedSent               int
	AuthAttempts           int
	VIN                    []byte
	Flag                   []byte
	Memory                 []byte
	DynamicDataIdentifiers []DynamicDataIdentifier
}

type DynamicDataIdentifier struct {
	DataIdentifier []byte // the ID used for this new identifier should start with F2/F3 to avoid collisions
	SourceType     byte   //0x01 == uds.DefineByIdentifier, 0x02 == uds.DefineByMemoryAddress
	Source         []byte // either DataIdentifier or MemoryAddress
	Size           uint   // the size of the target value
	SourceOffset   int    // an offset into the source
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
		if len(response) == 1 {
			// check for DynamicDataIdentifiers
			response = v.getDynamicallyDefinedDataIdentifier(dataIdentifier)
		}

	}
	//if we have values to respond with
	if len(response) > 1 {
		return response
	}
	// otherwise request out of range
	return []byte{uds.NR, uds.ReadDataByIdentifier, uds.ROOR}
}

func (v *VulnPoc) DynamicallyDefineDataIdentifier(payload []byte) []byte {
	/* this function supports three sub-functions:
	0x01 - defineByIdentifier
	0x02 - defineByMemoryAddress
	0x03 - clearDynamicallyDefinedDataIdentifier
	*/

	if payload[0] == 0x01 {
		return v.defineByIdentifier(payload[1:])
	}
	if payload[0] == 0x02 {
		return v.defineByMemoryAddress(payload[1:])
	}
	if payload[0] == 0x03 {
		return v.clearDynamicallyDefinedDataIdentifier(payload[1:])
	}
	// otherwise, subFunctionNotSupported (0x12)
	return []byte{uds.NR, uds.DynamicallyDefineDataIdentifier, uds.SFNS}

}

func (v *VulnPoc) defineByIdentifier(payload []byte) []byte {
	/*
		payload may contain multiple of the following layout:
		[0:2] dynamicallyDefinedDataIdentifier - 0xAABB
		[2:4] sourceDataIdentifier             - 0xCCDD
		[5]   positionInSourceDataRecord       - 0x01
		[6]   memorySize                       - 0xFF
	*/
	// check that the payload is well-formed by size
	if (len(payload) % 6) != 0 {
		return []byte{uds.NR, uds.DynamicallyDefineDataIdentifier, uds.IMLOIF}
	}

	// pull out our new DynamicDataIdentifier
	dynamicDid := payload[0:2]
	// iterate over each dynamic identifier
	for len(payload) != 0 {
		newIdentifier := DynamicDataIdentifier{}
		newIdentifier.SourceType = 0x01
		newIdentifier.DataIdentifier = dynamicDid
		newIdentifier.Source = payload[2:4]
		newIdentifier.Size = uint(payload[4])
		newIdentifier.SourceOffset = int(payload[5])

		//add to our instance array
		v.DynamicDataIdentifiers = append(v.DynamicDataIdentifiers, []DynamicDataIdentifier{newIdentifier}...)

		//cut our payload to the next
		payload = payload[6:]
	}
	response := []byte{uds.DynamicallyDefineDataIdentifier + 0x40}
	response = append(response, []byte{0x02}...)
	response = append(response, dynamicDid...)
	return response
}

func (v *VulnPoc) defineByMemoryAddress(payload []byte) []byte {
	/*
		payload may contain multiple of the following layout:
		[0:2] dynamicallyDefinedDataIdentifier             - 0xAABB
		[3] addressAndLengthFormatIdentifier               - 0xFF
		[4:4+addrSize]   memoryAddress				       - 0x01..addrSize
		[4+addrSize:(4+addrSize)+mSize]   memorySize       - 0xFF..mSize

	*/
	// pull out our new DynamicDataIdentifier
	dynamicDid := payload[0:2]
	addrSize, mSize := utils.ParseAddressAndLengthFormat(payload[2])

	memAddr := payload[3:(3 + addrSize)]
	memoryLen := payload[(3 + addrSize) : (3+addrSize)+mSize]
	newIdentifier := DynamicDataIdentifier{}
	newIdentifier.SourceType = 0x02
	newIdentifier.DataIdentifier = dynamicDid
	newIdentifier.Source = memAddr
	newIdentifier.Size, _ = utils.BytesToUInt(memoryLen)
	newIdentifier.SourceOffset = 0

	//add to our instance array
	v.DynamicDataIdentifiers = append(v.DynamicDataIdentifiers, []DynamicDataIdentifier{newIdentifier}...)
	// reslice the payload and iterate over the definitions
	payload = payload[3+len(memAddr)+len(memoryLen):]

	//if there are more
	for len(payload) != 0 {

		// check that the payload is well-formed by size - must be at least 5
		if len(payload) < 2 {
			return []byte{uds.NR, uds.DynamicallyDefineDataIdentifier, uds.IMLOIF}
		}
		memAddr := payload[:addrSize]
		memoryLen := payload[addrSize : addrSize+mSize]

		newIdentifier := DynamicDataIdentifier{}
		newIdentifier.SourceType = 0x02
		newIdentifier.DataIdentifier = dynamicDid
		newIdentifier.Source = memAddr
		newIdentifier.Size, _ = utils.BytesToUInt(memoryLen)
		newIdentifier.SourceOffset = 0

		//add to our instance array
		v.DynamicDataIdentifiers = append(v.DynamicDataIdentifiers, []DynamicDataIdentifier{newIdentifier}...)
		//cut our payload to the next

		payload = payload[len(memAddr)+len(memAddr):]
	}
	response := []byte{uds.DynamicallyDefineDataIdentifier + 0x40}
	response = append(response, []byte{0x02}...)
	response = append(response, dynamicDid...)
	return response

}

func (v *VulnPoc) clearDynamicallyDefinedDataIdentifier(payload []byte) []byte {
	/*
		payload may contain multiple of the following layout:
		[0:2] dynamicallyDefinedDataIdentifier             - 0xAABB
		[3] addressAndLengthFormatIdentifier               - 0xFF
		[4:4+addrSize]   memoryAddress				       - 0x01..addrSize
		[4+addrSize:(4+addrSize)+mSize]   memorySize       - 0xFF..mSize

	*/
	// pull out our new DynamicDataIdentifier
	dynamicDid := payload[0:2]
	removed := 0
	// iterate over all defined identifiers and remove

	for i := 0; i < len(v.DynamicDataIdentifiers); {
		if bytes.Equal(v.DynamicDataIdentifiers[i].DataIdentifier, dynamicDid) {
			//remove it from the array
			copy(v.DynamicDataIdentifiers[i:], v.DynamicDataIdentifiers[i+1:])
			v.DynamicDataIdentifiers = v.DynamicDataIdentifiers[:len(v.DynamicDataIdentifiers)-1]
			removed += 1
		} else {
			i++
		}

	}
	if removed == 0 {
		return []byte{uds.NR, uds.DynamicallyDefineDataIdentifier, uds.ROOR}
	}

	response := []byte{uds.DynamicallyDefineDataIdentifier + 0x40}
	response = append(response, []byte{0x03}...)
	response = append(response, dynamicDid...)
	return response
}

func (v *VulnPoc) getDynamicallyDefinedDataIdentifier(dataIdentifier []byte) []byte {
	response := []byte{}
	//iterate over defined identifiers and return hits
	for i := 0; i < len(v.DynamicDataIdentifiers); i++ {
		if bytes.Equal(v.DynamicDataIdentifiers[i].DataIdentifier, dataIdentifier) {
			dyndid := v.DynamicDataIdentifiers[i]
			if dyndid.SourceType == uds.DefineByIdentifier {
				// pass to ReadDataByIdentifier, remove the response byte
				response = append(response, v.ReadDataByIdentifier(dyndid.Source)[1:]...)
			}
			if dyndid.SourceType == uds.DefineByMemoryAddress {
				addr, _ := utils.BytesToUInt(dyndid.Source)
				mem, err := utils.ReadMemory(v.Memory, int(addr), int(dyndid.Size))
				if err != nil {
					return []byte{uds.NR, uds.ReadMemoryByAddress, uds.ROOR}
				}
				response = append(response, mem...)

			}
		}
	}
	if len(response) != 0 {
		return append([]byte{byte(uds.ReadDataByIdentifier + 0x40)}, response...)
	}
	return []byte{}
}

func main() {
	poc := &VulnPoc{Service: &node.DefaultService{}}
	poc.Flag = []byte("dynamically-define-your-way")
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
			ID:   "0x09",
			Name: "Level9",
			Description: `DynamicallyDefineDataIdentifier (0x2c)

DynamicallyDefineDataIdentifier allows the client to dynamically define a new DataIdentifier by DataIdentifier or 
MemoryAddress. This service provides a client the ability to create adhoc DataIdentifiers that can return multiple 
DataRecords with one request.

Example DynamicallyDefineDataIdentifier - DefineByIdentifier (0x01)  Message:
2c 01 f200 f190 01 00

Message Definition:
DynamicallyDefineDataIdentifier - 0x2c
Sub-Function - 0x01 - Define by DataIdentifier
dynamicallyDefinedDataIdentifier - 0xf200 - The new data identifier
sourceDataIdentifier - 0xf190 - The source data identifier (in this case, VIN)
positionInSourceDataRecord - 0x01 - The starting byte
memorySize - 0x00 - The offset in addition to the positionInSourceDataRecord

Positive Response:
6c 02f200
AddressAndLengthFormat - 0x02 - the requested sub-function value
dynamicallyDefinedDataIdentifier - 0xf200 - The new data identifier


This value can then be accessed using ReadDataByIdentifier (0x22):
# New identifier
TX: 22 f200
RX: 62 f1904154524544495331333337
# Source identifier
TX: 22 f190
RX: 62 f1904154524544495331333337


Example DynamicallyDefineDataIdentifier - DefineByAddress (0x02)  Message:
2c 02 f300 11 20 10

Message Definition:
DynamicallyDefineDataIdentifier - 0x2c
Sub-Function - 0x02 - Define by Address
dynamicallyDefinedDataIdentifier - 0xf300 - The new data identifier
addressAndLengthFormat - 0x11 - high nibble is length of memory size, low is length of Address 
MemoryAddress - 0x20 - memory address to read from
MemorySize - 0x10 - size of the memory to read

Full example:
# DynamicallyDefineDataIdentifier - DefineByAddress
TX: 2c 02 f300 11 20 10
RX: 6c 02f300
# ReadDataByIdentifier 
TX: 22 f300
RX: 62 41545245444953313333370000000000
# ReadMemoryBy Address 
TX: 23 11 20 10
RX: 63 41545245444953313333370000000000


Example DynamicallyDefineDataIdentifier - clearDynamicallyDefinedDataIdentifier (0x03)  Message:
2c 03 f300

Message Definition:
DynamicallyDefineDataIdentifier - 0x2c
Sub-Function - 0x03 - clearDynamicallyDefinedDataIdentifier
dynamicallyDefinedDataIdentifier - 0xf300 - The data identifier to remove

Full example:
# DynamicallyDefineDataIdentifier - DefineByAddress
TX: 2c 02 f300 11 20 10
RX: 6c 02f300
# ReadDataByIdentifier 
TX: 22 f300
RX: 62 41545245444953313333370000000000
# Clear DynamicallyDefinedDataIdentifier
TX: 2c 03 f300
RX: 6c 03f300
# DataIdentifier no longer available
TX: 22 f300
RX: 7f 2231

Dynamically created identifiers can also be built up using multiple records or requests
# DynamicallyDefineDataIdentifier - DefineByAddress with multiple addresses/lengths [20,10] [00,10] [20,10]
TX: 2c 02 f300 11 20 10 00 10 20 10
RX: 6c 02f300
TX: 22 f300
RX: 62 415452454449533133333700000000000000000000000000000000000000000041545245444953313333370000000000
# DynamicallyDefineDataIdentifier - DefineByIdentifier - adding the identifier 0xf190 to our previous identifier
TX: 2c 01 f300 f190 01 00
RX: 6c 02f300
# ReadDataByIdentifier - full value 
TX: 22 f300
RX: 62 415452454449533133333700000000000000000000000000000000000000000041545245444953313333370000000000f1904154524544495331333337
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
	x.AddHandler(uds.ECUReset, poc.ECUReset)
	x.AddHandler(uds.ReadMemoryByAddress, poc.ReadMemoryByAddress)
	x.AddHandler(uds.WriteMemoryByAddress, poc.WriteMemoryByAddress)
	x.AddHandler(uds.DynamicallyDefineDataIdentifier, poc.DynamicallyDefineDataIdentifier)
	if err := x.Start(); err != nil {
		panic(err)
	}
}
