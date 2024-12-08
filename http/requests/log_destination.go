package requests

import (
	"github.com/go-playground/validator/v10"
	"tedalogger-backend/models"
)

type CreateLogDestinationRequest struct {
	Type          models.LogDestinationType `json:"type" validate:"required,oneof=FTP SFTP Network Local"`
	ServerAddress string                    `json:"serverAddress,omitempty"`
	Username      string                    `json:"username,omitempty"`
	Password      string                    `json:"password,omitempty"`
	Port          int                       `json:"port,omitempty" validate:"omitempty,min=1,max=65535"`
	SSHKey        string                    `json:"sshKey,omitempty"`
	IPAddress     string                    `json:"ipAddress,omitempty"`
	FilePath      string                    `json:"filePath,omitempty"`
}

func (r *CreateLogDestinationRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}

type UpdateLogDestinationRequest struct {
	Type          models.LogDestinationType `json:"type" validate:"required,oneof=FTP SFTP Network Local"`
	ServerAddress string                    `json:"serverAddress,omitempty"`
	Username      string                    `json:"username,omitempty"`
	Password      string                    `json:"password,omitempty"`
	Port          int                       `json:"port,omitempty" validate:"omitempty,min=1,max=65535"`
	SSHKey        string                    `json:"sshKey,omitempty"`
	IPAddress     string                    `json:"ipAddress,omitempty"`
	FilePath      string                    `json:"filePath,omitempty"`
}

func (r *UpdateLogDestinationRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
