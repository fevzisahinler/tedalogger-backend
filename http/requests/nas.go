package requests

import (
	"github.com/go-playground/validator/v10"
)

type CreateOrUpdateNASRequest struct {
	Nasname           string `json:"nasname" validate:"required"`
	Shortname         string `json:"shortname"`
	Type              string `json:"type"`
	Port              int    `json:"port" validate:"required,numeric"`
	Secret            string `json:"secret" validate:"required"`
	Server            string `json:"server"`
	Community         string `json:"community"`
	Description       string `json:"description"`
	SMTPEnabled       bool   `json:"smtp_enabled"`
	Syslog5651Enabled bool   `json:"syslog_5651_enabled"`
}

func (r *CreateOrUpdateNASRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
