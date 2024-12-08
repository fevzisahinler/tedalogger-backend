package models

import "time"

type RadGroup struct {
	ID                    uint      `gorm:"primaryKey" json:"id"`
	RadiusGroupName       string    `gorm:"unique;not null" json:"radiusGroupName"`
	SessionTimeout        int       `json:"session_timeout"`
	IdleTimeout           int       `json:"idle_timeout"`
	SimultaneousUse       int       `json:"simultaneous_use"`
	Bandwidth             string    `json:"bandwidth"`
	TimeOfDayRestrictions string    `json:"time_of_day_restrictions"`
	Description           string    `json:"description"`
	CreatedAt             time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt             time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}
