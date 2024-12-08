package models

import (
	"time"
)

type LogDestinationType string

const (
	FTP     LogDestinationType = "FTP"
	SFTP    LogDestinationType = "SFTP"
	Network LogDestinationType = "Network"
	Local   LogDestinationType = "Local"
)

type LogDestination struct {
	ID            uint               `gorm:"primaryKey" json:"id"`
	Type          LogDestinationType `gorm:"type:varchar(20);not null" json:"type"`
	ServerAddress string             `json:"serverAddress,omitempty"`
	Username      string             `json:"username,omitempty"`
	Password      string             `json:"password,omitempty"`
	Port          int                `json:"port,omitempty"`
	SSHKeyPath    string             `json:"sshKeyPath,omitempty"`
	IPAddress     string             `json:"ipAddress,omitempty"`
	FilePath      string             `json:"filePath,omitempty"`
	CreatedAt     time.Time          `json:"createdAt"`
	UpdatedAt     time.Time          `json:"updatedAt"`
}
