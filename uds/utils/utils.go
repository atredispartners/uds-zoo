package utils

import (
	"encoding/binary"
	"errors"
)

// PopBytes: pops off count bytes from data and returns the modified input
// data := []bytes{1,2,3,4}
// new,data = PopBytes(data,2)
// new = {1,2}, data = {3,4}
func PopBytes(data []byte, count int) ([]byte, []byte, error) {
	if len(data) < count {
		return nil, data, errors.New("number of bytes to pop larger than data")
	}
	return data[:count], data[count:], nil
}

//WriteMemory: writes a value into a byte array at a given offset
// memory := []bytes{1,2,3,4,5,6,7,8,9,10}
// WriteMemory(&memory,[]byte{6,6,6},3)
// memory is now []bytes{1,2,3,6,6,6,7,8,9,10}
func WriteMemory(memory *[]byte, input []byte, offset int) error {
	//check if input is larger than target memory
	if len(input) > len((*memory)) {
		return errors.New("input larger than destination")
	}
	//check if input extends beyond end of memory
	if len(input)+offset > len((*memory)) {
		return errors.New("input does not fit within destination offset")
	}
	//write input to memory offset
	for i := 0; i < len(input); i++ {
		(*memory)[offset+i] = input[i]
	}

	return nil
}

//ReadMemory: returns a section of memory by offset and size
func ReadMemory(memory []byte, offset int, size int) ([]byte, error) {
	//check if the offset or size are beyond the target
	if offset > len(memory) || offset+size > len(memory) {
		return nil, errors.New("offset extends beyond memory bounds")
	}
	if size > len(memory) {
		return nil, errors.New("requested size larger than target memory")
	}

	//return slice of memory
	return memory[offset : offset+size], nil

}

//ReadMemory: returns a null terminated string from memory
func ReadMemoryStr(memory []byte, offset int) ([]byte, error) {
	//check if the offset or size are beyond the target
	if offset > len(memory) {
		return nil, errors.New("offset extends beyond memory bounds")
	}
	str := ""
	// iterate over memory[offset] until we hit a null
	for i := offset; i < len(memory); i++ {
		if memory[i] == 0x00 {
			return []byte(str), nil
		}
		str += string(memory[i])
	}

	//return slice of memory
	return []byte(str), nil

}

//XorBytes: xor's two equal length byte arrays
func XorBytes(src []byte, key []byte) ([]byte, error) {

	if len(src) != len(key) {
		return nil, errors.New("input bytes are not equal length")
	}
	output := make([]byte, len(src))
	for i := 0; i < len(src); i++ {
		output[i] = src[i] ^ key[i]
	}
	return output, nil
}

//BytesToInt32: turns a byte array of 4 or less len into an int32
func BytesToInt32(input []byte) (int32, error) {
	if len(input) <= 4 {
		padded := append(make([]byte, 4-len(input)), input...)
		return int32(binary.BigEndian.Uint32(padded)), nil
	}
	return 0, errors.New("input bytes longer than int32")
}

//BytesToUInt: turns a byte array of 8 or less into a uint
func BytesToUInt(input []byte) (uint, error) {
	if len(input) <= 8 {
		padded := append(make([]byte, 8-len(input)), input...)
		return uint(binary.BigEndian.Uint64(padded)), nil
	}
	return 0, errors.New("input bytes longer than 8")
}

//ParseAddressAndLengthFormat: parses an addressAndLengthFormatIdentifier
func ParseAddressAndLengthFormat(formatIdentfier byte) (addrSize int, mSize int) {
	addressLength := int(formatIdentfier & 0xf)
	sizeLength := int(formatIdentfier&0xf0) >> 4
	return addressLength, sizeLength
}
