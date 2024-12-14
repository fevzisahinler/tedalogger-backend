package requests

import "github.com/go-playground/validator/v10"

type SnmpStatsRequest struct {
    Target         string `json:"target" validate:"required,ip"`
    Port           uint16 `json:"port" validate:"required"`
    Version        string `json:"version" validate:"required,oneof=v2c v3"`
    Community      string `json:"community,omitempty"`
    UserName       string `json:"username,omitempty"`  
    AuthPassword   string `json:"auth_password,omitempty"`
    AuthProtocol   string `json:"auth_protocol,omitempty"`
    PrivPassword   string `json:"priv_password,omitempty"`
    PrivProtocol   string `json:"priv_protocol,omitempty"`
    SecurityLevel  string `json:"security_level,omitempty"`
    TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
    Retries        int    `json:"retries,omitempty"`
}

func (r *SnmpStatsRequest) Validate() error {
    validate := validator.New()
    return validate.Struct(r)
}
