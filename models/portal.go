// models/portal.go

package models

import (
	"time"

	"gorm.io/datatypes"
)

type Portal struct {
	ID               uint           `gorm:"primaryKey" json:"id"`
	PortalID         string         `gorm:"uniqueIndex;not null" json:"portalID"`
	Name             string         `gorm:"not null;unique" json:"name"`
	RadiusGroupName  string         `json:"radiusGroupName"`
	NasName          string         `json:"nasName"`
	LoginComponents  datatypes.JSON `json:"loginComponents"`
	SignupComponents datatypes.JSON `json:"signupComponents"`
	Theme            datatypes.JSON `json:"theme"`
	Logo             string         `json:"logo,omitempty"`
	Background       string         `json:"background,omitempty"`
	OtpEnabled       bool           `gorm:"default:false" json:"otpEnabled"`
	CreatedAt        time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt        time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
}

type PortalComponent struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	Label        string   `json:"label"`
	Placeholder  string   `json:"placeholder,omitempty"`
	Required     bool     `json:"required"`
	IsVisible    bool     `json:"isVisible"`
	Options      []string `json:"options,omitempty"`
	DefaultValue string   `json:"defaultValue,omitempty"`
	FontFamily   string   `json:"fontFamily,omitempty"`
	FontSize     string   `json:"fontSize,omitempty"`
	ButtonText   string   `json:"buttonText,omitempty"`
	TermsContent string   `json:"termsContent,omitempty"`
}

type Theme struct {
	BackgroundColor string `json:"backgroundColor"`
	FontFamily      string `json:"fontFamily"`
	ButtonColor     string `json:"buttonColor"`
	HeaderColor     string `json:"headerColor"`
	InputColor      string `json:"inputColor"`
	FontSize        string `json:"fontSize,omitempty"`
}
