package models

import (
	"time"
)

type User struct {
	ID          uint      `gorm:"column:id;primaryKey"`
	Username    string    `gorm:"unique;not null"`
	Password    string    `json:"-" gorm:"not null"`
	Name        string    `gorm:"not null"`
	Surname     string    `gorm:"not null"`
	Email       string    `gorm:"unique;not null"`
	PhoneNumber string    `gorm:"not null"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
	Roles       []Role    `gorm:"many2many:user_roles;"`
}
