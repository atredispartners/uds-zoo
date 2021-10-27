// +build !windows

package node

func buildDefaultListenerConfig(name string) ListenerConfig {
	return ListenerConfig{
		Network: "unix",
		Addr:    buildUnixSocketPath(name),
	}
}
