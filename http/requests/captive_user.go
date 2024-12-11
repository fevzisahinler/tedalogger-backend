// http/requests/captive_user.go

package requests

import (
	"github.com/go-playground/validator/v10"
)

type CaptiveUserRegisterRequest struct {
	PortalID      string                 `json:"portalID" validate:"required"`
	DynamicFields map[string]interface{} `json:"dynamic_fields,omitempty" validate:"required"`
}

func (r *CaptiveUserRegisterRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}

type VerifyOTPRequest struct {
	UserID uint   `json:"user_id" validate:"required"`
	OTP    string `json:"otp" validate:"required"`
}

func (r *VerifyOTPRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
