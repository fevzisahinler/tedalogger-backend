package models

import (
	"time"
)

type User struct {
	ID          uint   `gorm:"column:user_id;primaryKey"`
	Username    string `gorm:"unique;not null"`
	Password    string `gorm:"not null"`
	FullName    string
	Email       string `gorm:"unique"`
	PhoneNumber string
	CreatedAt   time.Time `gorm:"default:current_timestamp"`
	UpdatedAt   time.Time
	Roles       []Role `gorm:"many2many:user_roles;"`
}
