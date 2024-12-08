package requests

import (
	"github.com/go-playground/validator/v10"
	"tedalogger-backend/models"
)

type CreateSignSettingsRequest struct {
	FileSigningMethod models.FileSigningMethod `json:"fileSigningMethod" validate:"required,oneof='Self Signed Certificate' 'Kamu SM (Tübitak)'"`
	FileSizeLimitMB   int                      `json:"fileSizeLimitMB" validate:"required,min=0"`
	BackupFrequency   models.BackupFrequency   `json:"backupFrequency" validate:"required,oneof='1 hour' '3 hours' '6 hours' '12 hours' '24 hours'"`
}

func (r *CreateSignSettingsRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}

type UpdateSignSettingsRequest struct {
	FileSigningMethod models.FileSigningMethod `json:"fileSigningMethod" validate:"required,oneof='Self Signed Certificate' 'Kamu SM (Tübitak)'"`
	FileSizeLimitMB   int                      `json:"fileSizeLimitMB" validate:"required,min=0"`
	BackupFrequency   models.BackupFrequency   `json:"backupFrequency" validate:"required,oneof='1 hour' '3 hours' '6 hours' '12 hours' '24 hours'"`
}

func (r *UpdateSignSettingsRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
