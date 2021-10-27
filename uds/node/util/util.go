package util

// PopSubFun is a helper function that will remove the first byte off an array and return that byte
// and the tail.
func PopSubFunc(data []byte) (byte, []byte) {
	if len(data) == 1 {
		return data[0], []byte{}
	}
	if len(data) == 0 {
		return 0x00, []byte{}
	}
	return data[0], data[1:]
}
