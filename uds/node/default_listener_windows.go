package node

import (
	"crypto/rand"
	"math/big"
	"strconv"
)

func buildDefaultListenerConfig(name string) ListenerConfig {
	return ListenerConfig{
		Network: "tcp",
		Addr:    strconv.Itoa(randomPort()),
	}
}

func randomPort() int {
	x, _ := rand.Int(rand.Reader, big.NewInt(65535))
	return int(x.Int64())
}
