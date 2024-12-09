// http/requests/portal.go

package requests

import (
	"github.com/go-playground/validator/v10"
)

type ComponentRequest struct {
	ID             string   `json:"id" validate:"required"`
	Type           string   `json:"type" validate:"required"`
	Label          string   `json:"label" validate:"required"`
	Placeholder    string   `json:"placeholder"`
	Required       bool     `json:"required"`
	IsVisible      bool     `json:"isVisible"`
	Options        []string `json:"options"`
	DefaultValue   string   `json:"defaultValue"`
	FontFamily     string   `json:"fontFamily"`
	FontSize       string   `json:"fontSize"`
	ButtonText     string   `json:"buttonText"`
	OtpPlaceholder string   `json:"otpPlaceholder"`
}

type ThemeRequest struct {
	BackgroundColor string `json:"backgroundColor" validate:"required"`
	FontFamily      string `json:"fontFamily" validate:"required"`
	ButtonColor     string `json:"buttonColor" validate:"required"`
	HeaderColor     string `json:"headerColor" validate:"required"`
	InputColor      string `json:"inputColor" validate:"required"`
	FontSize        string `json:"fontSize"` // Optional
}

type CreateOrUpdatePortalRequest struct {
	PortalID         string             `json:"portalID" validate:"required"`
	Name             string             `json:"name" validate:"required"`
	RadiusGroupName  string             `json:"radiusGroupName" validate:"required"`
	NasName          string             `json:"nasName" validate:"required"`
	LoginComponents  []ComponentRequest `json:"loginComponents"`
	SignupComponents []ComponentRequest `json:"signupComponents"`
	Theme            ThemeRequest       `json:"theme" validate:"required"`
	Logo             string             `json:"logo"`
	Background       string             `json:"background"`
	OtpEnabled       bool               `json:"otpEnabled"` // Yeni alan eklendi
}

func (r *CreateOrUpdatePortalRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
