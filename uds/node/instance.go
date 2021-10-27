package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/atredispartners/uds-zoo/uds/store"
	"github.com/atredispartners/uds-zoo/uds/uds"
)

var (
	DONTREGISTERINSTANCE = false
)

// InstanceInfo is used to identify and describe a UDS node.
type InstanceInfo struct {
	ID          string
	Name        string
	Description string
}

type ListenerConfig struct {
	Network string
	Addr    string
}

type InstanceConfig struct {
	ControllerURL  string
	ListenerConfig ListenerConfig
	Info           InstanceInfo
	Service        Service
}

// Instance is used to launch and handle incoming messages to a service.
type Instance struct {
	service   Service
	info      InstanceInfo
	sidRoutes map[byte]func([]byte) []byte
	listener  ListenerConfig
	httpGWURL string
}

func buildOrUseListenerConfig(c ListenerConfig, name string) ListenerConfig {
	if c.Network == "" || c.Addr == "" {
		return buildDefaultListenerConfig(name)
	}
	return c
}

func buildUnixSocketPath(name string) string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "/tmp"
	}
	return fmt.Sprintf("%s/%s.uds.sock", cwd, name)
}

func validateInstanceConfig(c *InstanceConfig) error {
	if c.Info.Name == "" {
		return fmt.Errorf("config Info.Name can not be empty")
	}

	if c.Info.ID == "" {
		return fmt.Errorf("config Info.ID can not be empty")
	}

	if c.ControllerURL == "" {
		return fmt.Errorf("ControllerURL can not be empty")
	}

	if c.ListenerConfig.Network != "tcp" && c.ListenerConfig.Network != "unix" {
		return fmt.Errorf("ListenerConfig.Network is of unsupported type, must be unix or tcp")
	}
	return nil
}

// NewInstance returns an initialized instance that is ready to launch.
func NewInstance(c *InstanceConfig) (*Instance, error) {
	c.ListenerConfig = buildOrUseListenerConfig(c.ListenerConfig, c.Info.Name)
	if err := validateInstanceConfig(c); err != nil {
		return nil, err
	}
	return &Instance{
		info:      c.Info,
		service:   c.Service,
		sidRoutes: buildSIDRouting(c.Service),
		listener:  c.ListenerConfig,
		httpGWURL: c.ControllerURL,
	}, nil
}

// NewInstanceWithDefaultService returns an instance that uses
// DefaultService. It can be modified using AddHandler.
func NewInstanceWithDefaultService(c *InstanceConfig) (*Instance, error) {
	s := &DefaultService{}
	c.ListenerConfig = buildOrUseListenerConfig(c.ListenerConfig, c.Info.Name)
	if err := validateInstanceConfig(c); err != nil {
		return nil, err
	}
	return &Instance{
		info:      c.Info,
		service:   s,
		sidRoutes: buildSIDRouting(s),
		listener:  c.ListenerConfig,
		httpGWURL: c.ControllerURL,
	}, nil
}

// AddHandler creates or overwrites an existing service handler for an SID.
// Example:
// i.AddHandler(0x27, func(data []byte) []byte {
//	return []byte{0x63, 0x41, 0x41}
// })
func (i *Instance) AddHandler(sid byte, handler func([]byte) []byte) {
	i.sidRoutes[sid] = handler
}

func buildListener(c *ListenerConfig) (net.Listener, error) {
	switch c.Network {
	case "unix":
		os.Remove(c.Addr)
		return net.Listen("unix", c.Addr)
	case "tcp":
		return net.Listen("tcp", c.Addr)
	default:
		return nil, errors.New("unsupported listener type")
	}
}

func registerWithGateway(gwURL string, i *Instance) error {
	if DONTREGISTERINSTANCE {
		return nil
	}
	ir := store.InstanceRecord{
		ID:          i.info.ID,
		Name:        i.info.Name,
		Description: i.info.Description,
		Addr:        fmt.Sprintf("%s:%s", i.listener.Network, i.listener.Addr),
	}
	data, err := json.Marshal(&ir)
	if err != nil {
		return err
	}
	resp, err := http.Post(fmt.Sprintf("%s/instances", i.httpGWURL), "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("HTTP GW returned a non-202 status code %d", resp.StatusCode)
	}
	return nil
}

// Start launches an HTTP service for the instance bound an a unix socket.
// The routes include:
// POST /uds
func (i *Instance) Start() error {
	s := http.Server{}
	l, err := buildListener(&i.listener)
	if err != nil {
		return err
	}
	if err := registerWithGateway(i.httpGWURL, i); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/uds", i.handleUDS)
	s.Handler = mux
	return s.Serve(l)
}

func buildSIDRouting(s Service) map[byte]func([]byte) []byte {
	return map[byte]func([]byte) []byte{
		uds.ReadMemoryByAddress:      s.ReadMemoryByAddress,
		uds.DiagnosticSessionControl: s.DiagnosticSessionControl,
		uds.ReadDataByIdentifier:     s.ReadDataByIdentifier,
	}
}

func (i *Instance) handleUDS(w http.ResponseWriter, r *http.Request) {
	req, err := udsReqFromHTTPRequest(r)
	// TODO: We need to handle errors in a UDS sort of way.
	// And allow the user to overwrite the handler.
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f, ok := i.sidRoutes[req.SID]
	if !ok {
		// The provided SID was not in our sidRoutes, return Negative Response ServiceNotSupported 0x7F, req.SID , 0x11
		resp := UDSHTTPRequestResponse{
			SID:  hex.EncodeToString([]byte{uds.NR}),
			Data: hex.EncodeToString(i.service.NotImplemented(req.SID)),
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	udsResponse := f(req.Data)
	if len(udsResponse) < 1 {
		// TODO: This means we have a bad handler that's not returning data.
		// Allow user to overwrite
		http.Error(w, "UDS response was 0 length", http.StatusInternalServerError)
		return
	}
	resp := UDSHTTPRequestResponse{
		SID: hex.EncodeToString([]byte{udsResponse[0]}),
	}
	if len(udsResponse) > 1 {
		resp.Data = hex.EncodeToString(udsResponse[1:])
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func udsReqFromHTTPRequest(r *http.Request) (uds.Request, error) {
	// TODO: What should the default SID and data be be?
	var req UDSHTTPRequestResponse
	var udsReq uds.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return udsReq, err
	}
	sid, err := hex.DecodeString(req.SID)
	if err != nil {
		return udsReq, errors.New("invalid SID hex value")
	}
	if len(sid) != 1 {
		return udsReq, errors.New("SID is of unexpected length")
	}

	data, err := hex.DecodeString(req.Data)
	if err != nil {
		return udsReq, errors.New("invalid Data hex value")
	}

	udsReq.SID = sid[0]
	udsReq.Data = data

	return udsReq, nil
}

type UDSHTTPRequestResponse struct {
	SID  string `json:"sid"`
	Data string `json:"data"`
}
