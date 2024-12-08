package models

import (
	"time"
)

type FileSigningMethod string

const (
	SelfSignedCertificate FileSigningMethod = "Self Signed Certificate"
	KamuSM                FileSigningMethod = "Kamu SM"
)

type BackupFrequency string

const (
	OneHour         BackupFrequency = "1 hour"
	ThreeHours      BackupFrequency = "3 hours"
	SixHours        BackupFrequency = "6 hours"
	TwelveHours     BackupFrequency = "12 hours"
	TwentyFourHours BackupFrequency = "24 hours"
)

type SignSettings struct {
	ID                uint              `gorm:"primaryKey" json:"id"`
	FileSigningMethod FileSigningMethod `gorm:"type:varchar(50);not null" json:"fileSigningMethod"`
	FileSizeLimitMB   int               `gorm:"not null" json:"fileSizeLimitMB"`
	BackupFrequency   BackupFrequency   `gorm:"type:varchar(20);not null" json:"backupFrequency"`
	CreatedAt         time.Time         `json:"createdAt"`
	UpdatedAt         time.Time         `json:"updatedAt"`
}
