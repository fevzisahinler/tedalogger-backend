type SNMPConfig struct {
	Target          string
	Port            uint16
	Version         string
	Community       string
	UserName        string 
	AuthPassword    string
	AuthProtocol    string
	PrivPassword    string  
	PrivProtocol    string  
	SecurityLevel   string  
	TimeoutSeconds  int
	Retries         int
}