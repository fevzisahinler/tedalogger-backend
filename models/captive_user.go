package models

import (
	"time"

	"gorm.io/datatypes"
)

type CaptiveUser struct {
	ID            uint           `gorm:"primaryKey" json:"id"`
	PortalID      string         `gorm:"index;not null" json:"portalID"`
	TCKN          string         `gorm:"uniqueIndex;null" json:"tc_id,omitempty"`
	FirstName     string         `json:"first_name"`
	LastName      string         `gorm:"not null" json:"last_name"`
	Username      string         `gorm:"uniqueIndex;not null" json:"username"`
	Password      string         `gorm:"not null" json:"password"`
	Email         string         `gorm:"uniqueIndex;not null" json:"email"`
	Phone         string         `gorm:"uniqueIndex;not null" json:"phone"`
	DynamicFields datatypes.JSON `json:"dynamic_fields,omitempty"`
	OTPCode       string         `json:"otp_code,omitempty"`
	OTPExpiresAt  *time.Time     `json:"otp_expires_at,omitempty"`
	IsOTPVerified bool           `gorm:"default:false" json:"is_otp_verified"`
	CreatedAt     time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt     time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
}
