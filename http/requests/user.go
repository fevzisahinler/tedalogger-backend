package requests

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/go-playground/validator/v10"

	"tedalogger-backend/models"
)

type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
	Name        string `json:"name" validate:"required,max=20"`
	Surname     string `json:"surname" validate:"required,max=20"`
	Email       string `json:"email" validate:"required,email"`
	PhoneNumber string `json:"phoneNumber" validate:"required"`
}

func (u *CreateUserRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(u)
}

func HashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func (u *CreateUserRequest) ToModel() *models.User {
	return &models.User{
		Username:    u.Username,
		Password:    HashPassword(u.Password),
		Name:        u.Name,
		Surname:     u.Surname,
		Email:       u.Email,
		PhoneNumber: u.PhoneNumber,
	}
}

type UpdateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=100"`
	Password    string `json:"password,omitempty" validate:"omitempty,min=8"`
	Name        string `json:"name" validate:"required,max=20"`
	Surname     string `json:"surname" validate:"required,max=20"`
	Email       string `json:"email" validate:"required,email"`
	PhoneNumber string `json:"phoneNumber" validate:"required"`
}

func (u *UpdateUserRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(u)
}
