package uds

type Request struct {
	SID  byte
	Data []byte
}

type Response struct {
	SID  byte
	Data []byte
}

const (
	// UDS Services: name and mnemonic
	DiagnosticSessionControl = 0x10
	DSC
	ECUReset = 0x11
	ER
	SecurityAccess = 0x27
	SA
	CommunicationControl = 0x28
	CC
	TesterPresent = 0x3E
	TP
	AccessTimingParameter = 0x83
	ATP
	SecuredDataTransmission = 0x84
	SDT
	ControlDTCSetting = 0x85
	CDTCS
	ResponseOnEvent = 0x86
	ROE
	LinkControl = 0x87
	LC
	ReadDataByIdentifier = 0x22
	RDBI
	ReadMemoryByAddress = 0x23
	RMBA
	ReadScalingDataByIdentifier = 0x24
	RSDBI
	ReadDataByPeriodicIdentifier = 0x2A
	RDBPI
	DynamicallyDefineDataIdentifier = 0x2C
	DDDI
	WriteDataByIdentifier = 0x2E
	WDBI
	WriteMemoryByAddress = 0x3D
	WMBA
	ClearDiagnosticInformation = 0x14
	CDTCI
	ReadDTCInformation = 0x19
	RDTCI
	InputOutputControlByIdentifier = 0x2F
	IOCBI
	RoutineControl = 0x31
	RC
	RequestDownload = 0x34
	RD
	RequestUpload = 0x35
	RU
	TransferData = 0x36
	TD
	RequestTransferExit = 0x37
	RTE
)

// subfunction constants
const (
	HardReset = 0x01
	HR
	DefineByIdentifier
	KeyOffOnReset = 0x02
	KOFFONR
	DefineByMemoryAddress
	SoftReset = 0x03
	SR
	EnableRapidPowerShutDown = 0x04
	ERPSD
	DisableRapidPowerShutDown = 0x05
	DRPSD
)

// Response Code constants
const (
	GR      = 0x10
	SNS     = 0x11
	SFNS    = 0x12
	IMLOIF  = 0x13
	RTL     = 0x14
	BRR     = 0x21
	CNC     = 0x22
	RSE     = 0x24
	NRFSC   = 0x25
	FPEORA  = 0x26
	ROOR    = 0x31
	SAD     = 0x33
	IK      = 0x35
	ENOA    = 0x36
	RTDNE   = 0x37
	UDNA    = 0x70
	TDS     = 0x71
	GPF     = 0x72
	WBSC    = 0x73
	RCRRP   = 0x78
	SFNSIAS = 0x7E
	SNSIAS  = 0x7F
	NR
)

//Response Codes
var ResponseCodes = map[int]string{
	0x10: "General reject",
	0x11: "Service not supported",
	0x12: "Sub-Function not support",
	0x13: "InCorrect message length or invalid format",
	0x14: "Response too long",
	0x21: "Busy repeat request",
	0x22: "Conditions not correct",
	0x24: "Request sequence error",
	0x25: "No response from sub-net component",
	0x26: "Failure prevents execution of requested action",
	0x31: "Request out of range",
	0x33: "Security access denied",
	0x35: "Invalid key",
	0x36: "Exceeded number of attempts",
	0x37: "Required time delay not expired",
	0x38: "Reserved by Extended Data Link Security Document",
	0x70: "Upload/Download not accepted",
	0x71: "Transfer data suspended",
	0x72: "General programming failure",
	0x73: "Wrong block sequence counter",
	0x78: "Request correctly received, but response is pending",
	0x7E: "Sub-Function not supported in active session",
	0x7F: "Service not supported in active session",
	//conditional response codes
	0x81: "RPM too high",
	0x82: "RPM too low",
	0x83: "Engine is running",
	0x84: "Engine is not running",
	0x85: "Engine runtime too low",
	0x86: "Temperature too high",
	0x87: "Temperature too low",
	0x88: "Vehicle speed too high",
	0x89: "Vehicle speed too low",
	0x8A: "Throttle/Pedal too high",
	0x8B: "Throttle/Pedal too low",
	0x8C: "Transmission range not in neutral",
	0x8D: "Transmission range not in gear",
	0x8F: "Brake switches not closed",
	0x90: "Shift lever not in park",
	0x91: "Torque converter clutch locked",
	0x92: "Voltage too high",
	0x93: "Voltage too low",
}
