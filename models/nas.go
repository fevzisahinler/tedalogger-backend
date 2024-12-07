package models

import (
	"time"
)

type NAS struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	Nasname           string    `gorm:"not null" json:"nasname"`
	Shortname         string    `json:"shortname"`
	Type              string    `json:"type"`
	Port              int       `json:"port"` // Artık tek bir port alanı
	Secret            string    `gorm:"not null" json:"secret"`
	Server            string    `json:"server"`
	Community         string    `json:"community"`
	Description       string    `json:"description"`
	SMTPEnabled       bool      `json:"smtp_enabled"`
	Syslog5651Enabled bool      `json:"syslog_5651_enabled"`
	CreatedAt         time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (NAS) TableName() string {
	return "nas"
}
