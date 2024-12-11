// models/captive_user.go

package models

import (
	"time"
)

type CaptiveUser struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	PortalID      string     `gorm:"index;not null" json:"portalID"`
	TCKN          *string    `gorm:"null" json:"tc_id,omitempty"`
	FirstName     *string    `gorm:"null" json:"first_name,omitempty"`
	LastName      *string    `gorm:"null" json:"last_name,omitempty"`
	BirthDate     *int       `gorm:"null" json:"birth_date"`
	Username      *string    `gorm:"uniqueIndex;null" json:"username,omitempty"`
	Password      *string    `gorm:"null" json:"password,omitempty"` // Nullable yapıldı
	Email         *string    `gorm:"null" json:"email,omitempty"`
	Phone         *string    `gorm:"null" json:"phone,omitempty"`
	RadiusGroup   string     `gorm:"not null" json:"radius_group"`
	NASName       string     `gorm:"not null" json:"nas_name"`
	OTPCode       *string    `json:"otp_code,omitempty"`
	OTPExpiresAt  *time.Time `json:"otp_expires_at,omitempty"`
	IsOTPVerified bool       `gorm:"default:false" json:"is_otp_verified"`
	CreatedAt     time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt     time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}
